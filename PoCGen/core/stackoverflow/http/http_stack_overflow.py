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
    payload: Optional[str] = None,
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

# from __future__ import annotations

# from datetime import datetime
# from pathlib import Path
# import time
# from typing import List, Optional

# from rich.console import Console

# from PoCGen.config.config import SETTINGS
# from PoCGen.llm.client import ChatMessage, LLMClient
# from PoCGen.prompts.templates import build_prompt_stack_overflow_http
# from PoCGen.core.sampler import sample_target_with_playwright
# from PoCGen.core.target_profile import TargetSample
# from PoCGen.tools.getWeb import get_web_infomation
# from PoCGen.core.models import (
#     AttemptResult,
#     GenerationResult,
#     HTTPMessage,
#     ValidationResult,
#     VulnHandler,
# )
# from .postprocess import save_messages, split_messages
# from .validators import parse_and_validate
# from .remote_validator import validate_http_requests

# console = Console()


# class StackOverflowHTTPHandler(VulnHandler):
#     name = "stack_overflow_http"

#     def build_messages(
#         self,
#         description: str,
#         code_texts: List[str],
#         target: Optional[str],
#         attacker_url: str,
#         target_profile: Optional[str] = None,
#         validation_feedback: Optional[str] = None,
#     ) -> List[dict]:
#         msgs = build_prompt_stack_overflow_http(
#             description=description,
#             code_files=code_texts,
#             target=target,
#             attacker_url=None,
#             target_profile=target_profile,
#             validation_feedback=validation_feedback,
#         )
#         return [m.model_dump() for m in msgs]


# def generate_stack_overflow_http(
#     description: str,
#     code_texts: List[str],
#     target: Optional[str] = None,
#     vuln_type: Optional[str] = None,
#     temperature: float = 0.2,
#     max_tokens: int = 4000,
#     attacker_url: Optional[str] = None,
#     probe_target: bool = False,
#     auto_validate: bool = False,
#     max_iterations: Optional[int] = None,
#     stop_on_success: Optional[bool] = None,
#     monitor_timeout: Optional[float] = None,
#     cvenumber: Optional[str] = None,
#     login_url: Optional[str] = None,
#     login_username: Optional[str] = None,
#     login_password: Optional[str] = None,
#     login_user_field: str = "username",
#     login_pass_field: str = "password",
#     use_browser_login: bool = False,
#     browser_headless: Optional[bool] = None,
# ) -> GenerationResult:
#     handler_key = vuln_type or StackOverflowHTTPHandler.name
#     handler = StackOverflowHTTPHandler()
    
#     if cvenumber:
#         get_web_infomation(cvenumber)

#     chat_log_dir = Path(__file__).resolve().parent.parent.parent.parent / "logs" / "chat"
#     chat_log_dir.mkdir(parents=True, exist_ok=True)
#     chat_log_path = chat_log_dir / f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

#     def log_chat(text: str) -> None:
#         try:
#             ts = datetime.now().isoformat(timespec="seconds")
#             with open(chat_log_path, "a", encoding="utf-8") as fh:
#                 fh.write(f"[{ts}] {text}\n")
#         except Exception:
#             pass

#     log_chat(
#         "Initial input for Stack Overflow HTTP PoC Generation:\n"
#         f"description: {description}\n"
#         f"target: {target or '<none>'}\n"
#         f"vuln_type: {handler_key}\n"
#     )

#     max_iters = max(1, max_iterations or SETTINGS.max_iterations)
#     if not auto_validate:
#         max_iters = 1
#     stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
#     out_dir = SETTINGS.save_dir
#     attempts: List[AttemptResult] = []
#     feedback_text: Optional[str] = None
#     overall_success = False
#     last_raw_output = ""
#     last_requests: List[HTTPMessage] = []
#     last_saved_paths: List[str] = []
#     last_validation_results: Optional[List[ValidationResult]] = None

#     console.print("[cyan]Stack overflow detection mode: checking for service crashes (5xx HTTP errors or connection failures)[/cyan]")
    
#     conversation_messages: List[ChatMessage] = [ChatMessage(**m) for m in handler.build_messages(
#         description,
#         code_texts,
#         target,
#         "",
#         None,
#         None,
#     )]

#     generation_start_ts = time.time()

#     try:
#         target_profile_block: Optional[str] = None
#         sample_cookies_header: Optional[str] = None
#         if probe_target and target:
#             if use_browser_login:
#                 try:
#                     sample: TargetSample = sample_target_with_playwright(
#                         target,
#                         login_url=login_url,
#                         login_username=login_username,
#                         login_password=login_password,
#                         login_user_field=login_user_field,
#                         login_pass_field=login_pass_field,
#                         headless=browser_headless,
#                         capture_posts=True,
#                         capture_cookies=True,
#                         capture_socket_messages=False,
#                     )
#                     target_profile_block = sample.as_prompt_block()
#                     sample_cookies_header = sample.cookies_header
#                 except Exception as exc:
#                     console.print(f"[yellow]Warning: failed to probe target {target}: {exc}")
#             else:
#                 console.print("[yellow]probe_target currently requires --browser-login; skipping target sampling")

#         for attempt_index in range(max_iters):
#             console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters} for Stack Overflow[/bold]")

#             log_chat(f"Attempt {attempt_index + 1} starting")
#             if feedback_text:
#                 log_chat(f"Feedback provided to model:\n{feedback_text}")

#             messages: List[ChatMessage] = list(conversation_messages)
#             if target_profile_block:
#                 messages.append(ChatMessage(role="user", content=f"Updated target profile:\n{target_profile_block}"))
#             if feedback_text:
#                 messages.append(ChatMessage(role="user", content=f"Feedback from previous attempt:\n{feedback_text}"))

#             log_chat(
#                 "Model input messages:\n" +
#                 "\n".join(f"- {m.role}: {m.content}" for m in messages)
#             )

#             client = LLMClient()
#             try:
#                 raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
#             finally:
#                 client.close()

#             conversation_messages.append(ChatMessage(role="assistant", content=raw_output))
#             log_chat("Model output:\n" + raw_output)

#             raw_messages = split_messages(raw_output)
#             if not raw_messages and raw_output.strip():
#                 raw_messages = [raw_output.strip()]

#             if raw_messages:
#                 saved_paths = save_messages(raw_messages, out_dir)
#                 console.print(
#                     f"Saved {len(saved_paths)} PoC request(s) to: {out_dir}"
#                 )
#             else:
#                 saved_paths = []
#                 console.print(
#                     f"[yellow]Attempt {attempt_index + 1} produced no parseable HTTP request"
#                 )

#             requests: List[HTTPMessage] = []
#             parse_issues: List[str] = []
#             for idx, raw in enumerate(raw_messages):
#                 try:
#                     msg, errs = parse_and_validate(raw)
#                     requests.append(msg)
#                     if errs:
#                         for err in errs:
#                             parse_issues.append(f"Request #{idx}: {err}")
#                 except Exception as exc:
#                     parse_issues.append(f"Request #{idx} parse error: {exc}")
#                     requests.append(HTTPMessage(method="", path="", version="", headers={}, body=raw))

#             validation_results: Optional[List[ValidationResult]] = None
#             validation_error: Optional[str] = None
#             crash_detected = False
#             crash_summary: Optional[str] = None
            
#             # 核心：使用与命令注入相同的验证机制，但不同的成功判断标准
#             if auto_validate and target and requests:
#                 if sample_cookies_header:
#                     for req in requests:
#                         if "Cookie" not in req.headers:
#                             req.headers["Cookie"] = sample_cookies_header
#                 try:
#                     validation_results = validate_http_requests(requests, target)
                    
#                     # 分析验证结果，寻找服务崩溃的迹象
#                     for res in validation_results:
#                         if res.success:
#                             # 请求成功发送，检查是否是5xx服务器错误
#                             if res.status_code and 500 <= res.status_code < 600:
#                                 # 5xx状态码表示服务器内部错误，可能是栈溢出导致的崩溃
#                                 console.print(
#                                     f"[bold green]Request #{res.request_index} -> HTTP {res.status_code} - Service returned 5xx error (potential crash)![/bold green]"
#                                 )
#                                 crash_detected = True
#                                 crash_summary = f"HTTP {res.status_code} error detected"
#                             else:
#                                 # 正常响应（2xx/3xx/4xx），服务未崩溃
#                                 console.print(
#                                     f"[green]Request #{res.request_index} -> HTTP {res.status_code}"
#                                 )
#                         else:
#                             # 请求失败，检查是否为连接错误（服务可能崩溃）
#                             error_msg = res.error or "Unknown error"
#                             error_lower = error_msg.lower()
                            
#                             # 检查是否连接相关的错误（服务崩溃的迹象）
#                             if any(err_keyword in error_lower for err_keyword in [
#                                 "connection", "timeout", "reset", "refused", "unreachable", "aborted"
#                             ]):
#                                 console.print(
#                                     f"[bold green]Request #{res.request_index} validation failed ({error_msg}) - Service may have crashed![/bold green]"
#                                 )
#                                 crash_detected = True
#                                 crash_summary = f"Connection error: {error_msg}"
#                             else:
#                                 # 其他类型的失败
#                                 detail = error_msg
#                                 preview = (res.response_preview or "").strip()
#                                 if preview:
#                                     preview = preview[:200] + ("..." if len(preview) > 200 else "")
#                                     detail += f" | body: {preview}"
#                                 console.print(
#                                     f"[yellow]Request #{res.request_index} validation failed ({detail})"
#                                 )
#                 except Exception as exc:
#                     console.print(f"[yellow]Warning: validation failed: {exc}")
#                     validation_results = None
#                     validation_error = str(exc)
#                     # 验证过程本身的异常也可能是连接问题
#                     if "connection" in str(exc).lower() or "timeout" in str(exc).lower():
#                         console.print(f"[bold green]Validation exception may indicate service crash: {exc}[/bold green]")
#                         crash_detected = True
#                         crash_summary = f"Validation error: {exc}"

#             feedback_for_next = None
#             if not crash_detected:
#                 feedback_for_next = _build_stack_overflow_attempt_feedback(
#                     parse_issues,
#                     validation_results,
#                     validation_error,
#                 )

#             attempts.append(
#                 AttemptResult(
#                     attempt_index=attempt_index,
#                     raw_output=raw_output,
#                     requests=requests,
#                     saved_paths=saved_paths,
#                     validation_results=validation_results,
#                     monitor_hit=crash_detected,  # 复用monitor_hit字段表示崩溃检测成功
#                     monitor_summary=crash_summary,
#                     feedback=feedback_for_next,
#                 )
#             )

#             last_raw_output = raw_output
#             last_requests = requests
#             last_saved_paths = saved_paths
#             last_validation_results = validation_results
#             overall_success = overall_success or crash_detected
#             feedback_text = feedback_for_next

#             if crash_detected and stop_after_success:
#                 console.print("[bold green]Stack overflow detected! Stopping further attempts.[/bold green]")
#                 break

#             if attempt_index + 1 < max_iters:
#                 if feedback_text:
#                     console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
#                 elif not crash_detected:
#                     console.print("[yellow]No specific feedback generated; will request model to adjust strategy")

#         return GenerationResult(
#             raw_output=last_raw_output,
#             requests=last_requests,
#             saved_paths=last_saved_paths,
#             validation_results=last_validation_results,
#             attempts=attempts,
#             success=overall_success,
#         )
#     except Exception as e:
#         console.print(f"[red]Error during stack overflow PoC generation: {e}")
#         raise


# def _build_stack_overflow_attempt_feedback(
#     parse_issues: List[str],
#     validation_results: Optional[List[ValidationResult]],
#     validation_error: Optional[str] = None,
# ) -> Optional[str]:
#     """为栈溢出漏洞构建迭代反馈信息（完全基于验证结果）"""
#     messages: List[str] = []
#     if parse_issues:
#         bullet = "\n".join(f"- {issue}" for issue in parse_issues)
#         messages.append("Local HTTP parsing/validation issues detected:\n" + bullet)

#     validation_summaries: List[str] = []
#     failed_validation: List[ValidationResult] = []
#     if validation_results is not None:
#         for res in validation_results:
#             status = f"HTTP {res.status_code}" if res.status_code is not None else "no status"
#             url = res.url or "<no url>"
#             preview = (res.response_preview or "").strip()
#             if preview:
#                 preview = preview[:200] + ("..." if len(preview) > 200 else "")
#             detail_parts: List[str] = []
#             if res.error:
#                 detail_parts.append(res.error)
#             if preview:
#                 detail_parts.append(f"body: {preview}")
#             detail = "; ".join(detail_parts)

#             if res.success:
#                 # 检查是否是5xx错误
#                 if res.status_code and 500 <= res.status_code < 600:
#                     line = f"Request #{res.request_index}: success -> {status} ({url}) - Good! 5xx error indicates potential service crash."
#                 else:
#                     line = f"Request #{res.request_index}: success -> {status} ({url})"
#             else:
#                 # 检查是否连接错误
#                 if res.error and any(err_keyword in res.error.lower() for err_keyword in [
#                     "connection", "timeout", "reset", "refused", "unreachable", "aborted"
#                 ]):
#                     line = f"Request #{res.request_index}: connection error -> {res.error} - Service may have crashed!"
#                 else:
#                     failed_validation.append(res)
#                     line = f"Request #{res.request_index}: failure -> {status} ({url})"
#                     if not detail:
#                         detail = "no response"
#             if detail and "Good!" not in line and "crashed!" not in line:
#                 line += f"; {detail}"
#             validation_summaries.append(line)

#         if validation_summaries:
#             messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))

#     elif validation_error:
#         messages.append(f"Target validation did not run due to error: {validation_error}")
#     else:
#         messages.append("Target validation did not run or returned no results.")

#     # 栈溢出特定的反馈指导
#     messages.append(
#         "No stack overflow (service crash) detected. Adjust the payload to trigger buffer overflow:\n"
#         "1) **Payload Size**: Increase the length of input strings significantly (1000+ characters)\n"
#         "2) **Payload Content**: Try different patterns:\n"
#         "   - Long strings of 'A's (e.g., 'A' * 5000)\n"
#         "   - Format string payloads (e.g., '%s%n%s%n' repeated)\n"
#         "   - Binary data or null bytes\n"
#         "3) **Parameter Targeting**: Try different input parameters\n"
#         "4) **Request Format**: Ensure Content-Type matches payload format\n"
#         "5) **Success Indicators**: We're looking for:\n"
#         "   - HTTP 5xx status codes (500, 503, 504, etc.)\n"
#         "   - Connection errors (refused, timeout, reset)\n"
#         "   - Server not responding at all"
#     )

#     return "\n\n".join(messages) if messages else None


# from __future__ import annotations

# from datetime import datetime
# from pathlib import Path
# import time
# import asyncio
# from typing import List, Optional, Tuple, Dict
# import aiohttp
# from rich.console import Console

# from PoCGen.config.config import SETTINGS
# from PoCGen.llm.client import ChatMessage, LLMClient
# from PoCGen.prompts.templates import build_prompt_stack_overflow_http
# from PoCGen.core.sampler import sample_target_with_playwright
# from PoCGen.core.target_profile import TargetSample
# from PoCGen.tools.getWeb import get_web_infomation
# from PoCGen.core.models import (
#     AttemptResult,
#     GenerationResult,
#     HTTPMessage,
#     ValidationResult,
#     VulnHandler,
# )
# from .postprocess import save_messages, split_messages
# from .validators import parse_and_validate
# from .remote_validator import validate_http_requests

# console = Console()


# class StackOverflowHTTPHandler(VulnHandler):
#     name = "stack_overflow_http"

#     def build_messages(
#         self,
#         description: str,
#         code_texts: List[str],
#         target: Optional[str],
#         attacker_url: str,  # 保留参数以保持接口一致
#         target_profile: Optional[str] = None,
#         validation_feedback: Optional[str] = None,
#     ) -> List[dict]:
#         # 栈溢出不需要攻击机URL，但我们保留参数接口
#         msgs = build_prompt_stack_overflow_http(
#             description=description,
#             code_files=code_texts,
#             target=target,
#             attacker_url=None,  # 传入None，因为栈溢出提示词不需要攻击机URL
#             target_profile=target_profile,
#             validation_feedback=validation_feedback,
#         )
#         return [m.model_dump() for m in msgs]


# class StackOverflowDetector:
#     """栈溢出检测器 - 检测目标服务是否崩溃或返回5xx错误"""
    
#     def __init__(self, timeout: int = 10):
#         self.timeout = timeout
#         self.session = None
    
#     async def __aenter__(self):
#         self.session = aiohttp.ClientSession(
#             timeout=aiohttp.ClientTimeout(total=self.timeout),
#             connector=aiohttp.TCPConnector(ssl=False)
#         )
#         return self
    
#     async def __aexit__(self, exc_type, exc_val, exc_tb):
#         if self.session:
#             await self.session.close()
    
#     async def check_service_status(self, url: str) -> Tuple[bool, str, Optional[int]]:
#         """
#         检查服务状态
#         返回: (服务是否异常, 描述信息, HTTP状态码)
#         """
#         if not self.session:
#             self.session = aiohttp.ClientSession(
#                 timeout=aiohttp.ClientTimeout(total=self.timeout),
#                 connector=aiohttp.TCPConnector(ssl=False)
#             )
        
#         try:
#             async with self.session.get(url) as response:
#                 status_code = response.status
                
#                 # 判断成功条件：返回5xx状态码
#                 if 500 <= status_code < 600:
#                     return True, f"Service returned {status_code} error (indicating potential crash)", status_code
#                 else:
#                     return False, f"Service responded with {status_code} (not a crash indicator)", status_code
                    
#         except aiohttp.ClientConnectorError as e:
#             # 连接错误 - 服务可能已崩溃
#             return True, f"Connection error: {str(e)} (service may have crashed)", None
#         except aiohttp.ServerTimeoutError as e:
#             # 超时 - 服务可能已挂起
#             return True, f"Timeout: {str(e)} (service may be hanging)", None
#         except aiohttp.ClientResponseError as e:
#             if 500 <= e.status < 600:
#                 return True, f"Client response error {e.status}: {str(e)}", e.status
#             return False, f"Client response error {e.status}: {str(e)}", e.status
#         except Exception as e:
#             # 其他异常
#             return True, f"Exception during request: {str(e)}", None
    
#     def check_service_status_sync(self, url: str) -> Tuple[bool, str, Optional[int]]:
#         """同步版本的检查服务状态"""
#         try:
#             loop = asyncio.get_event_loop()
#         except RuntimeError:
#             loop = asyncio.new_event_loop()
#             asyncio.set_event_loop(loop)
        
#         return loop.run_until_complete(self.check_service_status(url))
    
#     def close(self):
#         """清理资源"""
#         if self.session:
#             try:
#                 loop = asyncio.get_event_loop()
#                 if loop.is_running():
#                     # 如果事件循环正在运行，使用create_task
#                     loop.create_task(self.session.close())
#                 else:
#                     # 否则同步关闭
#                     loop.run_until_complete(self.session.close())
#             except:
#                 pass


# def generate_stack_overflow_http(
#     description: str,
#     code_texts: List[str],
#     target: Optional[str] = None,
#     vuln_type: Optional[str] = None,
#     temperature: float = 0.2,
#     max_tokens: int = 4000,
#     attacker_url: Optional[str] = None,  # 栈溢出不需要攻击机URL
#     probe_target: bool = False,
#     auto_validate: bool = False,
#     max_iterations: Optional[int] = None,
#     stop_on_success: Optional[bool] = None,
#     monitor_timeout: Optional[float] = None,  # 保留参数但不使用
#     cvenumber: Optional[str] = None,
#     login_url: Optional[str] = None,
#     login_username: Optional[str] = None,
#     login_password: Optional[str] = None,
#     login_user_field: str = "username",
#     login_pass_field: str = "password",
#     use_browser_login: bool = False,
#     browser_headless: Optional[bool] = None,
# ) -> GenerationResult:
#     # 核心修改点1: 确定处理器类型
#     handler_key = vuln_type or StackOverflowHTTPHandler.name
#     handler = StackOverflowHTTPHandler()
    
#     if cvenumber:
#         get_web_infomation(cvenumber)

#     chat_log_dir = Path(__file__).resolve().parent.parent.parent.parent / "logs" / "chat"
#     chat_log_dir.mkdir(parents=True, exist_ok=True)
#     chat_log_path = chat_log_dir / f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

#     def log_chat(text: str) -> None:
#         try:
#             ts = datetime.now().isoformat(timespec="seconds")
#             with open(chat_log_path, "a", encoding="utf-8") as fh:
#                 fh.write(f"[{ts}] {text}\n")
#         except Exception:
#             pass

#     log_chat(
#         "Initial input for Stack Overflow HTTP PoC Generation:\n"
#         f"description: {description[:200]}...\n"  # 只记录描述的前200字符
#         f"target: {target or '<none>'}\n"
#         f"vuln_type: {handler_key}\n"
#         f"code_files_count: {len(code_texts)}\n"
#         f"total_code_size: {sum(len(c) for c in code_texts)} chars"
#     )

#     max_iters = max(1, max_iterations or SETTINGS.max_iterations)
#     if not auto_validate:
#         max_iters = 1
#     stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
#     out_dir = SETTINGS.save_dir
#     attempts: List[AttemptResult] = []
#     feedback_text: Optional[str] = None
#     overall_success = False
#     last_raw_output = ""
#     last_requests: List[HTTPMessage] = []
#     last_saved_paths: List[str] = []
#     last_validation_results: Optional[List[ValidationResult]] = None

#     # 栈溢出检测器
#     stack_overflow_detector: Optional[StackOverflowDetector] = None
#     if auto_validate and target:
#         stack_overflow_detector = StackOverflowDetector(timeout=10)
#         console.print("[cyan]Stack overflow detection mode: checking for service crashes (5xx or connection errors)[/cyan]")
    
#     # 构建初始对话消息
#     conversation_messages: List[ChatMessage] = [ChatMessage(**m) for m in handler.build_messages(
#         description,
#         code_texts,
#         target,
#         "",  # 传递空字符串，提示词函数会处理为None
#         None,
#         None,
#     )]

#     generation_start_ts = time.time()

#     try:
#         target_profile_block: Optional[str] = None
#         sample_cookies_header: Optional[str] = None
#         if probe_target and target:
#             if use_browser_login:
#                 try:
#                     sample: TargetSample = sample_target_with_playwright(
#                         target,
#                         login_url=login_url,
#                         login_username=login_username,
#                         login_password=login_password,
#                         login_user_field=login_user_field,
#                         login_pass_field=login_pass_field,
#                         headless=browser_headless,
#                         capture_posts=True,
#                         capture_cookies=True,
#                         capture_socket_messages=False,
#                     )
#                     target_profile_block = sample.as_prompt_block()
#                     sample_cookies_header = sample.cookies_header
#                 except Exception as exc:
#                     console.print(f"[yellow]Warning: failed to probe target {target}: {exc}")
#             else:
#                 console.print("[yellow]probe_target currently requires --browser-login; skipping target sampling")

#         for attempt_index in range(max_iters):
#             console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters} for Stack Overflow[/bold]")
#             console.print(f"[dim]Code context size: {sum(len(c) for c in code_texts)} characters[/dim]")

#             log_chat(f"Attempt {attempt_index + 1} starting")
#             if feedback_text:
#                 log_chat(f"Feedback provided to model:\n{feedback_text}")

#             messages: List[ChatMessage] = list(conversation_messages)
#             if target_profile_block:
#                 messages.append(ChatMessage(role="user", content=f"Updated target profile:\n{target_profile_block}"))
#             if feedback_text:
#                 messages.append(ChatMessage(role="user", content=f"Feedback from previous attempt:\n{feedback_text}"))

#             # 记录消息大小用于调试
#             total_chars = sum(len(m.content) for m in messages)
#             log_chat(
#                 f"Model input messages ({len(messages)} messages, {total_chars} chars):\n" +
#                 "\n".join(f"- {m.role}: {len(m.content)} chars" for m in messages)
#             )
            
#             if total_chars > 10000:
#                 console.print(f"[yellow]Warning: Large input context ({total_chars} chars) may cause timeout[/yellow]")

#             client = LLMClient()
#             try:
#                 raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
#                 console.print(f"[green]LLM response received ({len(raw_output)} chars)[/green]")
#             except Exception as e:
#                 console.print(f"[red]LLM API error: {e}[/red]")
#                 # 如果是超时错误，尝试减小输入大小
#                 if "timeout" in str(e).lower() and len(code_texts) > 0:
#                     console.print("[yellow]Reducing code context size due to timeout...[/yellow]")
#                     # 只保留前两个代码文件的内容，每个最多5000字符
#                     reduced_code_texts = []
#                     for i, code in enumerate(code_texts[:2]):  # 只取前两个文件
#                         reduced_code_texts.append(code[:5000] if len(code) > 5000 else code)
                    
#                     # 重新构建消息
#                     msgs = handler.build_messages(
#                         description,
#                         reduced_code_texts,
#                         target,
#                         "",
#                         target_profile_block,
#                         feedback_text,
#                     )
#                     messages = [ChatMessage(**m) for m in msgs]
#                     try:
#                         raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
#                         console.print(f"[green]LLM response received after reduction ({len(raw_output)} chars)[/green]")
#                     except Exception as retry_error:
#                         console.print(f"[red]Retry also failed: {retry_error}[/red]")
#                         raise
#                 else:
#                     raise
#             finally:
#                 client.close()

#             conversation_messages.append(ChatMessage(role="assistant", content=raw_output))
#             log_chat(f"Model output ({len(raw_output)} chars): {raw_output[:200]}...")

#             raw_messages = split_messages(raw_output)
#             if not raw_messages and raw_output.strip():
#                 raw_messages = [raw_output.strip()]

#             if raw_messages:
#                 saved_paths = save_messages(raw_messages, out_dir)
#                 console.print(
#                     f"Saved {len(saved_paths)} PoC request(s) to: {out_dir}"
#                 )
#             else:
#                 saved_paths = []
#                 console.print(
#                     f"[yellow]Attempt {attempt_index + 1} produced no parseable HTTP request"
#                 )

#             requests: List[HTTPMessage] = []
#             parse_issues: List[str] = []
#             for idx, raw in enumerate(raw_messages):
#                 try:
#                     msg, errs = parse_and_validate(raw)
#                     requests.append(msg)
#                     if errs:
#                         for err in errs:
#                             parse_issues.append(f"Request #{idx}: {err}")
#                 except Exception as exc:
#                     parse_issues.append(f"Request #{idx} parse error: {exc}")
#                     requests.append(HTTPMessage(method="", path="", version="", headers={}, body=raw))

#             validation_results: Optional[List[ValidationResult]] = None
#             validation_error: Optional[str] = None
#             exploit_success = False
#             crash_detection_summary: Optional[str] = None
            
#             # 核心修改点: 栈溢出成功判定标准
#             if auto_validate and target and requests:
#                 if sample_cookies_header:
#                     for req in requests:
#                         if "Cookie" not in req.headers:
#                             req.headers["Cookie"] = sample_cookies_header
                
#                 try:
#                     validation_results = validate_http_requests(requests, target)
                    
#                     # 检查每个请求的响应
#                     for res in validation_results:
#                         if res.success:
#                             # 请求成功发送并收到响应
#                             if res.status_code and 500 <= res.status_code < 600:
#                                 # 5xx 状态码 - 服务器错误，可能崩溃
#                                 console.print(
#                                     f"[bold green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url}) - Service returned 5xx error![/bold green]"
#                                 )
#                                 exploit_success = True
#                                 crash_detection_summary = f"HTTP {res.status_code} error detected"
#                             elif res.status_code and 400 <= res.status_code < 500:
#                                 # 4xx 状态码 - 客户端错误，不是栈溢出
#                                 console.print(
#                                     f"[yellow]Request #{res.request_index} -> HTTP {res.status_code} ({res.url}) - Client error[/yellow]"
#                                 )
#                             else:
#                                 # 2xx/3xx 状态码 - 正常响应，不是栈溢出
#                                 console.print(
#                                     f"[green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url}) - Service responding normally[/green]"
#                                 )
#                         else:
#                             # 请求失败 - 可能是服务崩溃
#                             error_msg = res.error or "Unknown error"
                            
#                             # 检查是否连接错误
#                             if any(err_keyword in error_msg.lower() for err_keyword in [
#                                 "connection", "timeout", "reset", "refused", "unreachable", "aborted"
#                             ]):
#                                 console.print(
#                                     f"[bold green]Request #{res.request_index} validation failed ({error_msg}) - Service may have crashed![/bold green]"
#                                 )
#                                 exploit_success = True
#                                 crash_detection_summary = f"Connection error: {error_msg}"
#                             else:
#                                 # 其他类型的失败
#                                 detail = error_msg
#                                 preview = (res.response_preview or "").strip()
#                                 if preview:
#                                     preview = preview[:200] + ("..." if len(preview) > 200 else "")
#                                     detail += f" | body: {preview}"
#                                 console.print(
#                                     f"[yellow]Request #{res.request_index} validation failed ({detail})"
#                                 )
                    
#                     # 如果验证结果为空或没有成功触发栈溢出，尝试检测目标服务状态
#                     if not exploit_success and stack_overflow_detector:
#                         console.print("[cyan]Checking if target service is still responsive...[/cyan]")
#                         try:
#                             # 尝试访问目标URL
#                             crash_detected, message, status_code = stack_overflow_detector.check_service_status_sync(target)
#                             if crash_detected:
#                                 console.print(f"[bold green]Service crash detected: {message}[/bold green]")
#                                 exploit_success = True
#                                 crash_detection_summary = message
#                             else:
#                                 console.print(f"[green]Service is still responsive: {message}[/green]")
#                         except Exception as e:
#                             console.print(f"[yellow]Service status check failed: {e}[/yellow]")
                            
#                 except Exception as exc:
#                     console.print(f"[yellow]Warning: validation failed: {exc}[/yellow]")
#                     validation_results = None
#                     validation_error = str(exc)
                    
#                     # 如果验证过程本身发生异常，可能是目标服务崩溃
#                     if "connection" in str(exc).lower() or "timeout" in str(exc).lower():
#                         console.print(f"[bold green]Validation exception may indicate service crash: {exc}[/bold green]")
#                         exploit_success = True
#                         crash_detection_summary = f"Validation error: {exc}"

#             feedback_for_next = None
#             if not exploit_success:
#                 feedback_for_next = _build_stack_overflow_attempt_feedback(
#                     parse_issues,
#                     validation_results,
#                     validation_error,
#                 )

#             attempts.append(
#                 AttemptResult(
#                     attempt_index=attempt_index,
#                     raw_output=raw_output,
#                     requests=requests,
#                     saved_paths=saved_paths,
#                     validation_results=validation_results,
#                     monitor_hit=exploit_success,  # 复用字段表示成功
#                     monitor_summary=crash_detection_summary,
#                     feedback=feedback_for_next,
#                 )
#             )

#             last_raw_output = raw_output
#             last_requests = requests
#             last_saved_paths = saved_paths
#             last_validation_results = validation_results
#             overall_success = overall_success or exploit_success
#             feedback_text = feedback_for_next

#             if exploit_success and stop_after_success:
#                 console.print("[bold green]Stack overflow detected! Stopping further attempts.[/bold green]")
#                 break

#             if attempt_index + 1 < max_iters:
#                 if feedback_text:
#                     console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)[/cyan]")
#                 elif not exploit_success:
#                     console.print("[yellow]No specific feedback generated; will request model to adjust strategy[/yellow]")

#         return GenerationResult(
#             raw_output=last_raw_output,
#             requests=last_requests,
#             saved_paths=last_saved_paths,
#             validation_results=last_validation_results,
#             attempts=attempts,
#             success=overall_success,
#         )
#     except Exception as e:
#         console.print(f"[red]Error during stack overflow PoC generation: {e}[/red]")
#         raise
#     finally:
#         # 清理栈溢出检测器
#         if stack_overflow_detector:
#             stack_overflow_detector.close()


# def _build_stack_overflow_attempt_feedback(
#     parse_issues: List[str],
#     validation_results: Optional[List[ValidationResult]],
#     validation_error: Optional[str] = None,
# ) -> Optional[str]:
#     """为栈溢出漏洞构建迭代反馈信息。"""
#     messages: List[str] = []
#     if parse_issues:
#         bullet = "\n".join(f"- {issue}" for issue in parse_issues)
#         messages.append("Local HTTP parsing/validation issues detected:\n" + bullet)

#     validation_summaries: List[str] = []
#     failed_validation: List[ValidationResult] = []
#     if validation_results is not None:
#         for res in validation_results:
#             status = f"HTTP {res.status_code}" if res.status_code is not None else "no status"
#             url = res.url or "<no url>"
#             preview = (res.response_preview or "").strip()
#             if preview:
#                 preview = preview[:200] + ("..." if len(preview) > 200 else "")
#             detail_parts: List[str] = []
#             if res.error:
#                 detail_parts.append(res.error)
#             if preview:
#                 detail_parts.append(f"body: {preview}")
#             detail = "; ".join(detail_parts)

#             if res.success:
#                 # 检查是否为5xx错误
#                 if res.status_code and 500 <= res.status_code < 600:
#                     line = f"Request #{res.request_index}: success -> {status} ({url}) - 5xx error detected, good!"
#                 else:
#                     line = f"Request #{res.request_index}: success -> {status} ({url})"
#             else:
#                 # 检查是否可能是服务崩溃的连接错误
#                 if res.error and any(err_keyword in res.error.lower() for err_keyword in [
#                     "connection", "timeout", "reset", "refused", "unreachable", "aborted"
#                 ]):
#                     line = f"Request #{res.request_index}: connection error -> {res.error} - Service may have crashed!"
#                 else:
#                     failed_validation.append(res)
#                     line = f"Request #{res.request_index}: failure -> {status} ({url})"
#                     if not detail:
#                         detail = "no response"
#             if detail and "This may indicate" not in line and "good!" not in line:
#                 line += f"; {detail}"
#             validation_summaries.append(line)

#         if validation_summaries:
#             messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))

#     elif validation_error:
#         messages.append(f"Target validation did not run due to error: {validation_error}")
#     else:
#         messages.append("Target validation did not run or returned no results.")

#     # 核心修改点: 移除监控相关反馈，专注于栈溢出漏洞特征
#     if parse_issues or failed_validation:
#         messages.append(
#             "Adjust along the following tracks before the next attempt:\n"
#             "1) Payload Construction: Focus on the vulnerable parameter(s) that accept user input. Construct payloads that cause buffer overflow. "
#             "   This may include sending extremely long strings, format strings, or specifically crafted binary data via multipart/form-data or raw body.\n"
#             "2) Error Analysis: We are looking for either:\n"
#             "   a) HTTP 5xx status codes (500, 503, etc.) - indicating server internal error\n"
#             "   b) Connection errors (connection refused, timeout, reset) - indicating the service may have crashed\n"
#             "3) Request Structure: Ensure the Content-Type header matches the payload (e.g., 'application/x-www-form-urlencoded', 'multipart/form-data', 'application/json', or plain text).\n"
#             "4) Crash Indicators: If you get a normal response (2xx/3xx/4xx), the payload likely didn't trigger the overflow. Try different overflow techniques:\n"
#             "   - Increase payload length gradually\n"
#             "   - Try different memory corruption techniques (heap vs stack)\n"
#             "   - Add NOP sleds and shellcode if appropriate\n"
#             "   - Try different parameter injection points"
#         )
#     else:
#         # 即使解析和验证都通过，但没有触发5xx或连接错误，也需要调整
#         messages.append(
#             "No stack overflow detected. The payload needs adjustment:\n"
#             "1) Increase the size of buffer overflow payloads\n"
#             "2) Try different memory corruption techniques (off-by-one, heap spraying, etc.)\n"
#             "3) Target different parameters or endpoints\n"
#             "4) Adjust the payload to bypass potential mitigations (ASLR, stack cookies, etc.)\n"
#             "5) Consider using format string vulnerabilities if buffer overflow doesn't work"
#         )

#     return "\n\n".join(messages) if messages else None