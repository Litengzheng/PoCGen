from __future__ import annotations

import argparse
import os
from typing import List

from PoCGen.core.generator import generate_poc
from PoCGen.core.ingest import read_code_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate HTTP PoCs for command injection using an LLM")
    parser.add_argument("--desc", required=False, default=None, help="Path to vulnerability description text file (optional)")
    parser.add_argument("--code", nargs="+", required=True, help="One or more code file paths or globs")
    parser.add_argument("--target", help="Optional target base URL")
    parser.add_argument("--vuln-type", default="command_injection_http", help="Vulnerability type handler key")
    parser.add_argument("--temperature", type=float, default=0.1, help="LLM generation temperature")
    parser.add_argument("--max-tokens", type=int, default=65535)
    parser.add_argument("--attacker", default=None, help="攻击机 URL（用于 wget 取回 net.sh），默认从配置 POCGEN_ATTACKER_URL 读取")
    parser.add_argument("--probe-target", action="store_true", help="在生成前主动访问 target，采集响应样本并提供给 LLM")
    parser.add_argument("--auto-validate", action="store_true", help="生成后自动向 target 发送 PoC 进行验证（需 target 可访问）")
    parser.add_argument("--max-iters", type=int, default=None, help="最大尝试次数（默认读取配置 POCGEN_MAX_ITERS）")
    parser.add_argument("--monitor-timeout", type=float, default=None, help="每次验证后等待攻击机 wget 回调的秒数")
    parser.add_argument("--stop-on-success", dest="stop_on_success", action="store_true", help="监测到 wget 回调后立即停止后续尝试")
    parser.add_argument("--no-stop-on-success", dest="stop_on_success", action="store_false", help="即便检测到 wget 回调也继续剩余尝试")
    parser.set_defaults(stop_on_success=None)
    parser.add_argument("--login-url", default=None, help="可选，登录请求的完整 URL，缺省时使用 target")
    parser.add_argument("--login-username", default=None, help="可选，登录用户名，缺省不传；若仅给密码，则用户名为空字符串")
    parser.add_argument("--login-password", default=None, help="可选，登录密码")
    parser.add_argument("--login-user-field", default="username", help="登录表单用户名字段名，默认 username")
    parser.add_argument("--login-pass-field", default="password", help="登录表单密码字段名，默认 password")
    parser.add_argument("--browser-login", action="store_true", help="使用 Playwright 浏览器登录以获取 cookie 后再验证")
    parser.add_argument("--browser-headful", action="store_true", help="浏览器登录时显示界面（headful），默认无头模式")
    parser.add_argument("--CVENumber",  default=None, help="浏览器登录时显示界面（headful），默认无头模式")
    args = parser.parse_args()

    if args.desc:
        with open(args.desc, "r", encoding="utf-8", errors="ignore") as f:
            description = f.read()
    else:
        description = ""

    code_texts: List[str] = read_code_files(args.code)

    result = generate_poc(
        description=description,
        code_texts=code_texts,
        target=args.target,
        vuln_type=args.vuln_type,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        attacker_url=args.attacker,
        probe_target=args.probe_target,
        auto_validate=args.auto_validate,
        max_iterations=args.max_iters,
        stop_on_success=args.stop_on_success,
        monitor_timeout=args.monitor_timeout,
        cvenumber=args.CVENumber,
        login_url=args.login_url,
        login_username=args.login_username,
        login_password=args.login_password,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        use_browser_login=args.browser_login,
        browser_headless=None if not args.browser_headful else False,
    )

    print("\nGenerated and saved the following PoC files:")
    for p in result.saved_paths:
        print(p)


if __name__ == "__main__":
    main()
