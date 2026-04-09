from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
import tempfile
import subprocess
import sys
import os
from typing import List, Optional
from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_stack_overflow_python
from PoCGen.core.sampler import sample_target_with_playwright
from PoCGen.core.target_profile import TargetSample
from PoCGen.tools.getWeb import get_web_infomation
from PoCGen.core.models import (
    AttemptResult,
    GenerationResult,
    HTTPMessage,
    ValidationResult,
    VulnHandler,
)
from .postprocess import save_python_code

console = Console()


class StackOverflowPythonHandler(VulnHandler):
    name = "stack_overflow_python_script"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        attacker_url: str,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
    ) -> List[dict]:
        msgs = build_prompt_stack_overflow_python(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=attacker_url,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]


def generate_stack_overflow_python(
    description: str,
    code_texts: List[str],
    target: Optional[str] = None,
    vuln_type: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 4000,
    payload: Optional[str] = None,
    attacker_url: Optional[str] = None,
    probe_target: bool = False,
    auto_validate: bool = False,
    max_iterations: Optional[int] = None,
    stop_on_success: Optional[bool] = None,
    monitor_timeout: Optional[float] = None,
    cvenumber: Optional[str] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    use_browser_login: bool = False,
    browser_headless: Optional[bool] = None,
) -> GenerationResult:
    handler_key = vuln_type or StackOverflowPythonHandler.name
    handler = StackOverflowPythonHandler()
    
    if cvenumber:
        get_web_infomation(cvenumber)

    # 生成主时间戳，用于整个生成过程
    main_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    chat_log_dir = Path(__file__).resolve().parent.parent.parent.parent / "logs" / "chat"
    chat_log_dir.mkdir(parents=True, exist_ok=True)
    chat_log_path = chat_log_dir / f"chat_{main_timestamp}.log"

    def log_chat(text: str) -> None:
        try:
            ts = datetime.now().isoformat(timespec="seconds")
            with open(chat_log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {text}\n")
        except Exception:
            pass

    log_chat(
        "Initial input for Stack Overflow Python PoC Generation:\n"
        f"description: {description[:200]}...\n"
        f"target: {target or '<none>'}\n"
        f"vuln_type: {handler_key}\n"
        f"main_timestamp: {main_timestamp}\n"
    )

    max_iters = max(1, max_iterations or SETTINGS.max_iterations)
    if not auto_validate:
        max_iters = 1
    stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
    out_dir = SETTINGS.save_dir
    attempts: List[AttemptResult] = []
    feedback_text: Optional[str] = None
    overall_success = False
    last_raw_output = ""
    last_saved_paths: List[str] = []

    console.print(f"[cyan]Stack overflow detection mode: 生成Python PoC脚本 (timestamp: {main_timestamp})[/cyan]")
    
    conversation_messages: List[ChatMessage] = [ChatMessage(**m) for m in handler.build_messages(
        description,
        code_texts,
        target,
        "",
        None,
        None,
    )]

    generation_start_ts = time.time()

    try:
        target_profile_block: Optional[str] = None
        sample_cookies_header: Optional[str] = None
        if probe_target and target:
            if use_browser_login:
                try:
                    sample: TargetSample = sample_target_with_playwright(
                        target,
                        login_url=login_url,
                        login_username=login_username,
                        login_password=login_password,
                        login_user_field=login_user_field,
                        login_pass_field=login_pass_field,
                        headless=browser_headless,
                        capture_posts=True,
                        capture_cookies=True,
                        capture_socket_messages=False,
                    )
                    target_profile_block = sample.as_prompt_block()
                    sample_cookies_header = sample.cookies_header
                except Exception as exc:
                    console.print(f"[yellow]Warning: failed to probe target {target}: {exc}")
            else:
                console.print("[yellow]probe_target currently requires --browser-login; skipping target sampling")

        for attempt_index in range(max_iters):
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters} for Stack Overflow (Python Script)[/bold]")

            log_chat(f"Attempt {attempt_index + 1} starting")
            if feedback_text:
                log_chat(f"Feedback provided to model:\n{feedback_text}")

            messages: List[ChatMessage] = list(conversation_messages)
            if target_profile_block:
                messages.append(ChatMessage(role="user", content=f"Updated target profile:\n{target_profile_block}"))
            if feedback_text:
                messages.append(ChatMessage(role="user", content=f"Feedback from previous attempt:\n{feedback_text}"))

            log_chat(
                "Model input messages:\n" +
                "\n".join(f"- {m.role}: {len(m.content)} chars" for m in messages)
            )

            client = LLMClient()
            try:
                raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
                console.print(f"[green]LLM响应接收 ({len(raw_output)} 字符)[/green]")
            except Exception as e:
                console.print(f"[red]LLM API错误: {e}[/red]")
                # 如果是超时错误，尝试减小输入
                if "timeout" in str(e).lower() and len(code_texts) > 0:
                    console.print("[yellow]由于超时，减小代码上下文大小...[/yellow]")
                    reduced_code_texts = [code[:3000] for code in code_texts[:2]]
                    
                    msgs = handler.build_messages(
                        description,
                        reduced_code_texts,
                        target,
                        "",
                        target_profile_block,
                        feedback_text,
                    )
                    messages = [ChatMessage(**m) for m in msgs]
                    try:
                        raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
                        console.print(f"[green]LLM响应接收 ({len(raw_output)} 字符)[/green]")
                    except Exception as retry_error:
                        console.print(f"[red]重试也失败: {retry_error}[/red]")
                        raise
                else:
                    raise
            finally:
                client.close()

            conversation_messages.append(ChatMessage(role="assistant", content=raw_output))
            log_chat(f"Model output ({len(raw_output)} chars): {raw_output[:200]}...")

            # 保存Python代码，使用主时间戳
            saved_paths = save_python_code(raw_output, out_dir, main_timestamp, attempt_index)
            if saved_paths:
                console.print(f"[green]保存PoC脚本到: {saved_paths[0]}[/green]")
            else:
                console.print("[yellow]未保存Python脚本[/yellow]")
                saved_paths = []

            # 验证Python脚本
            validation_result = None
            exploit_success = False
            validation_summary = None
            
            if auto_validate and target and saved_paths:
                console.print("[cyan]执行生成的Python PoC脚本...[/cyan]")
                try:
                    # 执行Python脚本
                    script_path = saved_paths[0]
                    result = execute_python_script(script_path, target, sample_cookies_header)
                    
                    if result["success"]:
                        exploit_success = result["crash_detected"]
                        validation_summary = result["summary"]
                        
                        if exploit_success:
                            console.print(f"[bold green]栈溢出检测成功！{validation_summary}[/bold green]")
                        else:
                            console.print(f"[yellow]未检测到栈溢出: {validation_summary}[/yellow]")
                    else:
                        console.print(f"[red]脚本执行失败: {result['error']}[/red]")
                        
                except Exception as e:
                    console.print(f"[red]验证过程中出错: {e}[/red]")

            feedback_for_next = None
            if not exploit_success:
                feedback_for_next = _build_python_attempt_feedback(
                    raw_output,
                    validation_summary,
                )

            attempts.append(
                AttemptResult(
                    attempt_index=attempt_index,
                    raw_output=raw_output,
                    requests=[],  # 没有HTTP请求
                    saved_paths=saved_paths,
                    validation_results=None,
                    monitor_hit=exploit_success,
                    monitor_summary=validation_summary,
                    feedback=feedback_for_next,
                )
            )

            last_raw_output = raw_output
            last_saved_paths = saved_paths
            overall_success = overall_success or exploit_success
            feedback_text = feedback_for_next

            if exploit_success and stop_after_success:
                console.print("[bold green]检测到栈溢出！停止后续尝试。[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]为下一次尝试准备反馈（反馈已记录，不打印到控制台）[/cyan]")
                elif not exploit_success:
                    console.print("[yellow]未生成特定反馈；将要求模型调整策略[/yellow]")

        return GenerationResult(
            raw_output=last_raw_output,
            requests=[],
            saved_paths=last_saved_paths,
            validation_results=None,
            attempts=attempts,
            success=overall_success,
        )
    except Exception as e:
        console.print(f"[red]生成栈溢出PoC时出错: {e}[/red]")
        raise


def execute_python_script(script_path: str, target: str, cookies_header: Optional[str] = None) -> dict:
    """执行Python脚本并分析结果"""
    result = {
        "success": False,
        "crash_detected": False,
        "summary": "",
        "error": None
    }
    
    try:
        # 在临时目录中执行脚本
        temp_dir = tempfile.mkdtemp()
        script_name = os.path.basename(script_path)
        
        # 复制脚本到临时目录
        import shutil
        temp_script = os.path.join(temp_dir, script_name)
        shutil.copy2(script_path, temp_script)
        
        # 设置环境变量
        env = os.environ.copy()
        if target:
            env["TARGET_URL"] = target
        
        # 执行脚本
        process = subprocess.run(
            [sys.executable, temp_script],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=temp_dir,
            env=env
        )
        
        output = process.stdout + "\n" + process.stderr
        
        # 分析输出
        result["success"] = process.returncode == 0
        
        # 检查是否有栈溢出迹象
        if "成功" in output or "crash" in output.lower() or "崩溃" in output:
            result["crash_detected"] = True
        elif "500" in output or "503" in output or "504" in output:
            result["crash_detected"] = True
        elif "ConnectionError" in output or "Timeout" in output:
            result["crash_detected"] = True
        
        # 提取摘要
        lines = output.split('\n')
        summary_lines = []
        for line in lines[-10:]:  # 取最后10行
            if any(keyword in line.lower() for keyword in ["成功", "失败", "状态码", "error", "crash", "崩溃"]):
                summary_lines.append(line.strip())
        
        result["summary"] = " | ".join(summary_lines[:3])
        
        # 清理
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    except subprocess.TimeoutExpired:
        result["error"] = "脚本执行超时（可能服务崩溃）"
        result["crash_detected"] = True
    except Exception as e:
        result["error"] = str(e)
    
    return result


def _build_python_attempt_feedback(
    raw_output: str,
    validation_summary: Optional[str] = None,
) -> Optional[str]:
    """为Python代码版本的栈溢出检测构建反馈"""
    messages = []
    
    # 检查生成的代码质量
    if "import requests" not in raw_output:
        messages.append("生成的代码缺少必要的导入语句（如import requests）。")
    
    if "def " not in raw_output and "class " not in raw_output:
        messages.append("生成的代码没有定义函数或类，可能不是一个完整的可执行脚本。")
    
    if "requests.post" not in raw_output and "requests.get" not in raw_output:
        messages.append("生成的代码没有发送HTTP请求。")
    
    if validation_summary:
        messages.append(f"执行结果: {validation_summary}")
    
    if messages:
        messages.append("\n改进建议:")
        messages.append("1. 确保生成完整的Python脚本，包含所有必要的导入")
        messages.append("2. 代码应该定义一个主函数来发送HTTP请求")
        messages.append("3. 包含缓冲区溢出payload，如长字符串、格式字符串等")
        messages.append("4. 添加错误处理，捕获连接错误和超时")
        messages.append("5. 输出详细的结果信息，便于分析")
        messages.append("6. 根据目标服务调整Content-Type和请求格式")
        
        return "\n".join(messages)
    
    return None