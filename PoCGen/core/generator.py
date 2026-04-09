from __future__ import annotations
from typing import Callable, Dict, List, Optional, Type

from PoCGen.config.config import SETTINGS
from .command_injection.http.http_command_injection import (
    CommandInjectionHTTPHandler,
    generate_command_injection_http,
)
from .command_injection.socket.socket_command_injection import (
    CommandInjectionSocketHandler,
    generate_command_injection_socket,
)
from .stackoverflow.http.http_stack_overflow import (
    StackOverflowHTTPHandler,
    generate_stack_overflow_http,
)

from .cross_site_scripting.http_cross_site_scripting import (
    CrossSiteScriptingHTTPHandler,
    generate_cross_site_scripting_http,
)

from .stackoverflow.python.python_stack_overflow import (
    StackOverflowPythonHandler,
    generate_stack_overflow_python,
)

from PoCGen.core.path_traversal.http_path_traversal import (
    PathTraversalHTTPHandler,
    generate_path_traversal_http,
)
from .models import GenerationResult, VulnHandler


HANDLERS: Dict[str, Type[VulnHandler]] = {
    CommandInjectionHTTPHandler.name: CommandInjectionHTTPHandler,
    CommandInjectionSocketHandler.name: CommandInjectionSocketHandler,
    StackOverflowHTTPHandler.name: StackOverflowHTTPHandler,
    CrossSiteScriptingHTTPHandler.name: CrossSiteScriptingHTTPHandler,
    StackOverflowPythonHandler.name: StackOverflowPythonHandler,
    PathTraversalHTTPHandler.name: PathTraversalHTTPHandler,
}

HandlerEntryPoint = Callable[..., GenerationResult]
HANDLER_ENTRYPOINTS: Dict[str, HandlerEntryPoint] = {}


def get_handler(vuln_type: Optional[str] = None) -> VulnHandler:
    key = vuln_type or SETTINGS.default_vuln_type
    cls = HANDLERS.get(key)
    if not cls:
        raise ValueError(f"Unsupported vuln type: {key}")
    return cls()


def generate_poc(
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
    cvenumber:Optional[str] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    use_browser_login: bool = False,
    browser_headless: Optional[bool] = None,
) -> GenerationResult:
    selected_vuln_type = vuln_type or SETTINGS.default_vuln_type
    handler_entry = HANDLER_ENTRYPOINTS.get(selected_vuln_type)
    if not handler_entry:
        raise ValueError(f"Unsupported vuln type: {selected_vuln_type}")

    return handler_entry(
        description=description,
        code_texts=code_texts,
        target=target,
        vuln_type=selected_vuln_type,
        temperature=temperature,
        max_tokens=max_tokens,
        payload=payload,
        probe_target=probe_target,
        auto_validate=auto_validate,
        max_iterations=max_iterations,
        stop_on_success=stop_on_success,
        monitor_timeout=monitor_timeout,
        cvenumber=cvenumber,
        login_url=login_url,
        login_username=login_username,
        login_password=login_password,
        login_user_field=login_user_field,
        login_pass_field=login_pass_field,
        use_browser_login=use_browser_login,
        browser_headless=browser_headless,
    )

HANDLER_ENTRYPOINTS[CommandInjectionHTTPHandler.name] = generate_command_injection_http
HANDLER_ENTRYPOINTS[CommandInjectionSocketHandler.name] = generate_command_injection_socket
HANDLER_ENTRYPOINTS[StackOverflowHTTPHandler.name] = generate_stack_overflow_http
HANDLER_ENTRYPOINTS[CrossSiteScriptingHTTPHandler.name] = generate_cross_site_scripting_http 
HANDLER_ENTRYPOINTS[StackOverflowPythonHandler.name] = generate_stack_overflow_python
HANDLER_ENTRYPOINTS[PathTraversalHTTPHandler.name] = generate_path_traversal_http
