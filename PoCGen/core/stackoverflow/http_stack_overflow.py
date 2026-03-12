from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_stack_overflow_http
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
from .postprocess import save_messages, split_messages
from .validators import parse_and_validate
from .remote_validator import validate_http_requests

console = Console()


class StackOverflowHTTPHandler(VulnHandler):
    # 核心修改点1: 处理器名称
    name = "stack_overflow_http"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        attacker_url: str,  # 保留参数以保持接口一致
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
    ) -> List[dict]:
        # 核心修改点2: 调用针对栈溢出漏洞的提示词构建函数
        msgs = build_prompt_stack_overflow_http(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=attacker_url,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]


def generate_stack_overflow_http(
    description: str,
    code_texts: List[str],
    target: Optional[str] = None,
    vuln_type: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 4000,
    attacker_url: Optional[str] = None,  # 保留参数但不使用
    probe_target: bool = False,
    auto_validate: bool = False,
    max_iterations: Optional[int] = None,
    stop_on_success: Optional[bool] = None,
    monitor_timeout: Optional[float] = None,  # 保留参数但不使用
    cvenumber: Optional[str] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    use_browser_login: bool = False,
    browser_headless: Optional[bool] = None,
) -> GenerationResult:
    # 核心修改点3: 确定处理器类型
    handler_key = vuln_type or StackOverflowHTTPHandler.name
    handler = StackOverflowHTTPHandler()
    if cvenumber:
        get_web_infomation(cvenumber)

    chat_log_dir = Path(__file__).resolve().parent.parent.parent.parent / "logs" / "chat"
    chat_log_dir.mkdir(parents=True, exist_ok=True)
    chat_log_path = chat_log_dir / f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    def log_chat(text: str) -> None:
        try:
            ts = datetime.now().isoformat(timespec="seconds")
            with open(chat_log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {text}\n")
        except Exception:
            pass

    log_chat(
        "Initial input for Stack Overflow HTTP PoC Generation:\n"
        f"description: {description}\n"
        f"target: {target or '<none>'}\n"
        f"vuln_type: {handler_key}\n"
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
    last_requests: List[HTTPMessage] = []
    last_saved_paths: List[str] = []
    last_validation_results: Optional[List[ValidationResult]] = None

    # 核心修改点4: 移除所有攻击机监控相关代码
    # 栈溢出成功判定将基于HTTP响应状态码（500等）或连接失败
    
    conversation_messages: List[ChatMessage] = [ChatMessage(**m) for m in handler.build_messages(
        description,
        code_texts,
        target,
        attacker_url or "",  # 传递空字符串
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
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters} for Stack Overflow[/bold]")

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
                "\n".join(f"- {m.role}: {m.content}" for m in messages)
            )

            client = LLMClient()
            try:
                raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
            finally:
                client.close()

            conversation_messages.append(ChatMessage(role="assistant", content=raw_output))
            log_chat("Model output:\n" + raw_output)

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

            validation_results: Optional[List[ValidationResult]] = None
            validation_error: Optional[str] = None
            # 核心修改点5: 栈溢出成功判定标准
            exploit_success = False
            if auto_validate and target and requests:
                if sample_cookies_header:
                    for req in requests:
                        if "Cookie" not in req.headers:
                            req.headers["Cookie"] = sample_cookies_header
                try:
                    validation_results = validate_http_requests(requests, target)
                    for res in validation_results:
                        if res.success:
                            # 成功发送请求但需要检查是否为栈溢出成功
                            if res.status_code and 500 <= res.status_code < 600:
                                console.print(
                                    f"[bold green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url}) - Potential stack overflow success![/bold green]"
                                )
                                exploit_success = True
                            else:
                                console.print(
                                    f"[green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url})"
                                )
                        else:
                            # 核心修改点6: 将连接失败也视为可能的成功
                            if res.error and any(err_keyword in res.error.lower() for err_keyword in [
                                "connection", "timeout", "reset", "refused", "unreachable", "aborted"
                            ]):
                                console.print(
                                    f"[bold green]Request #{res.request_index} validation failed ({res.error}) - Potential stack overflow success (service crashed)![/bold green]"
                                )
                                exploit_success = True
                            else:
                                detail = res.error or (f"HTTP {res.status_code}" if res.status_code else "no response")
                                preview = (res.response_preview or "").strip()
                                if preview:
                                    preview = preview[:200] + ("..." if len(preview) > 200 else "")
                                    detail += f" | body: {preview}"
                                console.print(
                                    f"[yellow]Request #{res.request_index} validation failed ({detail})"
                                )
                except Exception as exc:
                    console.print(f"[yellow]Warning: validation failed: {exc}")
                    validation_results = None
                    validation_error = str(exc)
                    # 如果验证过程本身发生异常，可能是目标服务崩溃
                    if "connection" in str(exc).lower() or "timeout" in str(exc).lower():
                        console.print(f"[bold green]Validation exception may indicate service crash: {exc}[/bold green]")
                        exploit_success = True

            feedback_for_next = None
            if not exploit_success:
                # 核心修改点7: 调整反馈信息，移除监控相关，专注于HTTP响应
                feedback_for_next = _build_stack_overflow_attempt_feedback(
                    parse_issues,
                    validation_results,
                    validation_error,
                )

            attempts.append(
                AttemptResult(
                    attempt_index=attempt_index,
                    raw_output=raw_output,
                    requests=requests,
                    saved_paths=saved_paths,
                    validation_results=validation_results,
                    monitor_hit=exploit_success,  # 复用字段表示成功
                    monitor_summary=f"Stack overflow detected via HTTP {validation_results[0].status_code if validation_results and validation_results[0].status_code else 'connection error'}" if exploit_success and validation_results else None,
                    feedback=feedback_for_next,
                )
            )

            last_raw_output = raw_output
            last_requests = requests
            last_saved_paths = saved_paths
            last_validation_results = validation_results
            overall_success = overall_success or exploit_success
            feedback_text = feedback_for_next

            if exploit_success and stop_after_success:
                console.print("[bold green]Stack overflow detected! Stopping further attempts.[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
                elif not exploit_success:
                    console.print("[yellow]No specific feedback generated; will request model to adjust strategy")

        return GenerationResult(
            raw_output=last_raw_output,
            requests=last_requests,
            saved_paths=last_saved_paths,
            validation_results=last_validation_results,
            attempts=attempts,
            success=overall_success,
        )
    except Exception as e:
        console.print(f"[red]Error during stack overflow PoC generation: {e}")
        raise


def _build_stack_overflow_attempt_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    validation_error: Optional[str] = None,
) -> Optional[str]:
    """为栈溢出漏洞构建迭代反馈信息。"""
    messages: List[str] = []
    if parse_issues:
        bullet = "\n".join(f"- {issue}" for issue in parse_issues)
        messages.append("Local HTTP parsing/validation issues detected:\n" + bullet)

    validation_summaries: List[str] = []
    failed_validation: List[ValidationResult] = []
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
                detail_parts.append(f"body: {preview}")
            detail = "; ".join(detail_parts)

            if res.success and res.status_code and 500 <= res.status_code < 600:
                # 5xx 状态码是期望的，但这里只记录，不视为失败
                line = f"Request #{res.request_index}: success -> {status} ({url}) - Good! This indicates a server error."
                if detail:
                    line += f"; {detail}"
                validation_summaries.append(line)
            elif res.success:
                line = f"Request #{res.request_index}: success -> {status} ({url})"
                if detail:
                    line += f"; {detail}"
                validation_summaries.append(line)
            else:
                # 检查是否可能是服务崩溃的连接错误
                if res.error and any(err_keyword in res.error.lower() for err_keyword in [
                    "connection", "timeout", "reset", "refused", "unreachable", "aborted"
                ]):
                    line = f"Request #{res.request_index}: connection error -> {res.error} - This may indicate service crash!"
                else:
                    failed_validation.append(res)
                    line = f"Request #{res.request_index}: failure -> {status} ({url})"
                    if not detail:
                        detail = "no response"
                if detail and "This may indicate" not in line:
                    line += f"; {detail}"
                validation_summaries.append(line)

        if validation_summaries:
            messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))

    elif validation_error:
        messages.append(f"Target validation did not run due to error: {validation_error}")
    else:
        messages.append("Target validation did not run or returned no results.")

    # 核心修改点8: 移除监控相关反馈，专注于栈溢出漏洞特征
    if parse_issues or failed_validation:
        messages.append(
            "Adjust along the following tracks before the next attempt:\n"
            "1) Payload Construction: Focus on the vulnerable parameter(s) that accept user input. Construct payloads that cause buffer overflow. "
            "   This may include sending extremely long strings, format strings, or specifically crafted binary data via multipart/form-data or raw body.\n"
            "2) Error Analysis: We are looking for either:\n"
            "   a) HTTP 5xx status codes (500, 503, etc.) - indicating server internal error\n"
            "   b) Connection errors (connection refused, timeout, reset) - indicating the service may have crashed\n"
            "3) Request Structure: Ensure the Content-Type header matches the payload (e.g., 'application/x-www-form-urlencoded', 'multipart/form-data', 'application/json', or plain text).\n"
            "4) Crash Indicators: If you get a normal response (2xx/3xx/4xx), the payload likely didn't trigger the overflow. Try different overflow techniques:\n"
            "   - Increase payload length gradually\n"
            "   - Try different memory corruption techniques (heap vs stack)\n"
            "   - Add NOP sleds and shellcode if appropriate\n"
            "   - Try different parameter injection points"
        )
    else:
        # 即使解析和验证都通过，但没有触发5xx或连接错误，也需要调整
        messages.append(
            "No stack overflow detected. The payload needs adjustment:\n"
            "1) Increase the size of buffer overflow payloads\n"
            "2) Try different memory corruption techniques (off-by-one, heap spraying, etc.)\n"
            "3) Target different parameters or endpoints\n"
            "4) Adjust the payload to bypass potential mitigations (ASLR, stack cookies, etc.)\n"
            "5) Consider using format string vulnerabilities if buffer overflow doesn't work"
        )

    return "\n\n".join(messages) if messages else None