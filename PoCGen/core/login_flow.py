from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.core.logger import _log, _append_login_chat

BUSY_INDICATOR_SELECTORS = [
    "[aria-busy=\"true\"]",
    "[data-loading=\"true\"]",
    "[data-busy=\"true\"]",
    "[role=\"progressbar\"]",
    ".loading",
    ".loading-indicator",
    ".spinner",
    ".spin",
    ".ant-spin",
    ".ant-spin-spinning",
    ".el-loading-mask",
    ".MuiCircularProgress-root",
    ".login-btn-spinner-wrapper",
    ".login-btn-animation.animation-active",
]


@dataclass
class LoginResult:
    user_entry: Optional[Dict[str, Any]]
    pass_entry: Optional[Dict[str, Any]]
    login_scenario: str
    clicked_login: bool
    pre_login_url: Optional[str]


def _describe_button(btn) -> str:
    try:
        tag = (btn.evaluate("e => e.tagName") or "").lower()
        btn_type = (btn.get_attribute("type") or "").lower()
        btn_id = btn.get_attribute("id") or ""
        btn_cls = btn.get_attribute("class") or ""
        return f"{tag}[type={btn_type}] id={btn_id} class={btn_cls}"
    except Exception:
        return "<unknown>"


def _collect_buttons(page) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    buttons_info: List[Dict[str, Any]] = []
    visible_entries: List[Dict[str, Any]] = []
    selector = (
        "button, input[type='button'], input[type='submit'], input[type='reset'], input[type='image'], "
        "a[href], a[role], [role='button'], [role='link'], [role='menuitem'], [role='option'], [role='tab'], [role='switch'], "
        "[role='checkbox'], [role='radio'], [onclick], [data-clickable], [data-action], [aria-pressed], [tabindex], "
        "div[class*='button'], div[class*='btn'], span[class*='button'], span[class*='btn'], div[tabindex], span[tabindex]"
    )
    try:
        nodes = page.query_selector_all(selector)
        for idx, btn in enumerate(nodes):
            try:
                tag = (btn.evaluate("e => e.tagName") or "").lower()
            except Exception:
                tag = ""
            if tag in {"svg", "img", "path", "canvas", "script", "style"}:
                continue
            try:
                if not btn.is_visible():
                    continue
            except Exception:
                continue
            text = (btn.inner_text() or "").strip()
            value = (btn.get_attribute("value") or "").strip()
            btn_type = (btn.get_attribute("type") or "").strip()
            btn_id = btn.get_attribute("id") or ""
            btn_class = btn.get_attribute("class") or ""
            aria = btn.get_attribute("aria-label") or ""
            role = btn.get_attribute("role") or ""
            href = btn.get_attribute("href") or ""
            tabindex = btn.get_attribute("tabindex") or ""
            onclick = btn.get_attribute("onclick") or ""
            form_meta = None
            try:
                form_meta = btn.evaluate(
                    """
                    (el) => {
                        let p = el;
                        while (p) {
                            if (p.tagName && p.tagName.toLowerCase() === 'form') {
                                return {
                                    method: (p.getAttribute('method') || '').toLowerCase(),
                                    action: p.getAttribute('action') || ''
                                };
                            }
                            p = p.parentElement;
                        }
                        return null;
                    }
                    """
                )
            except Exception:
                form_meta = None
            label = text or value or href or aria or btn_id or "<no-text>"
            buttons_info.append(
                {
                    "index": idx,
                    "text": text,
                    "value": value,
                    "type": btn_type or tag,
                    "id": btn_id,
                    "class": btn_class,
                    "aria": aria,
                    "role": role,
                    "href": href,
                    "tabindex": tabindex,
                    "onclick": bool(onclick),
                    "form_method": (form_meta or {}).get("method") or "",
                    "form_action": (form_meta or {}).get("action") or "",
                }
            )
            visible_entries.append(
                {
                    "index": idx,
                    "handle": btn,
                    "label": label,
                    "descriptor": _describe_button(btn),
                }
            )
    except Exception as exc:
        _log(f"collect buttons failed: {exc}")
    return buttons_info, visible_entries


def _collect_inputs(page) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    inputs_info: List[Dict[str, Any]] = []
    entries: List[Dict[str, Any]] = []
    selector = (
        "input, textarea, select, [contenteditable], [role='textbox'], [role='combobox'], [role='searchbox'], [role='spinbutton']"
    )
    try:
        nodes = page.query_selector_all(selector)
        for idx, node in enumerate(nodes):
            try:
                tag = (node.evaluate("e => e.tagName") or "").lower()
            except Exception:
                tag = ""
            if tag in {"svg", "img", "path", "canvas", "script", "style"}:
                continue
            try:
                visible = node.is_visible()
            except Exception:
                visible = False
            try:
                disabled = node.is_disabled()
            except Exception:
                disabled = False
            input_type = (node.get_attribute("type") or "").lower()
            name = node.get_attribute("name") or ""
            placeholder = node.get_attribute("placeholder") or ""
            label = node.get_attribute("aria-label") or ""
            css_class = node.get_attribute("class") or ""
            role = node.get_attribute("role") or ""
            contenteditable = node.get_attribute("contenteditable") or ""
            tabindex = node.get_attribute("tabindex") or ""
            try:
                text = (node.inner_text() or "").strip()
            except Exception:
                text = ""
            value_attr = node.get_attribute("value") or ""
            fillable = (
                tag in {"input", "textarea"}
                or (contenteditable and contenteditable.lower() != "false")
                or role in {"textbox", "searchbox"}
            )
            field_meta = {
                "field_index": idx,
                "tag": tag,
                "type": input_type,
                "name": name,
                "placeholder": placeholder,
                "aria": label,
                "class": css_class,
                "visible": visible,
                "disabled": disabled,
                "role": role,
                "tabindex": tabindex,
                "contenteditable": contenteditable,
                "text": text,
                "value": value_attr,
            }
            inputs_info.append(field_meta)
            entries.append(
                {
                    "index": idx,
                    "handle": node,
                    "visible": visible,
                    "disabled": disabled,
                    "meta": field_meta,
                    "descriptor": _describe_input(node),
                    "fillable": fillable,
                }
            )
    except Exception as exc:
        _log(f"collect inputs failed: {exc}")
    return inputs_info, entries


def _describe_input(node) -> str:
    try:
        tag = (node.evaluate("e => e.tagName") or "").lower()
        input_type = (node.get_attribute("type") or "").lower()
        name = node.get_attribute("name") or ""
        placeholder = node.get_attribute("placeholder") or ""
        aria = node.get_attribute("aria-label") or ""
        role = node.get_attribute("role") or ""
        return f"{tag}[type={input_type}] role={role} name={name} placeholder={placeholder} aria={aria}"
    except Exception:
        return "<input>"


def _click_button_with_strategy(
    button_entries: List[Dict[str, Any]],
    buttons_info: List[Dict[str, Any]],
    purpose: str,
    keywords: Optional[List[str]] = None,
    chat_log_path: Optional[Path] = None,
) -> bool:
    if not button_entries:
        _log(f"no visible buttons available for {purpose}")
        return False

    def _click(entry: Dict[str, Any], reason: str) -> bool:
        try:
            entry["handle"].click(timeout=5000)
            _log(
                f"clicked {purpose} button idx={entry['index']} label='{entry['label']}' via {reason}"
            )
            return True
        except Exception as exc:
            _log(f"click {purpose} button failed: {exc}")
            return False

    lowered = [(entry, (entry["label"] or "").lower()) for entry in button_entries]
    for kw in keywords or []:
        kw_lower = kw.lower()
        for entry, label_lower in lowered:
            if kw_lower and kw_lower in label_lower:
                if _click(entry, f"keyword '{kw}'"):
                    return True

    llm_choice = _llm_pick_login_button(buttons_info, purpose=purpose, chat_log_path=chat_log_path)
    if llm_choice:
        try:
            idx_sel = llm_choice.get("button_index")
        except Exception:
            idx_sel = None
        if idx_sel is not None:
            for entry, _ in lowered:
                if entry["index"] == idx_sel:
                    if _click(entry, "LLM suggestion"):
                        return True

    return _click(button_entries[0], "fallback-first")


def wait_for_page_idle(page, label: str, total_timeout: int = 30000) -> bool:
    deadline = time.time() + total_timeout / 1000.0
    last_state = ""
    last_busy = False
    last_url = ""
    while time.time() < deadline:
        try:
            status = page.evaluate(
                "(selectors) => {"
                "  const state = (document.readyState || '').toLowerCase();"
                "  const isVisible = (el) => {"
                "    if (!el) return false;"
                "    const style = window.getComputedStyle(el);"
                "    if (!style) return false;"
                "    if (style.visibility === 'hidden' || style.display === 'none' || parseFloat(style.opacity || '1') === 0) {"
                "      return false;"
                "    }"
                "    if (el.hasAttribute('aria-hidden') && (el.getAttribute('aria-hidden') || '').toLowerCase() === 'true') {"
                "      return false;"
                "    }"
                "    if (!el.offsetParent && style.position !== 'fixed' && style.position !== 'sticky') {"
                "      return false;"
                "    }"
                "    return true;"
                "  };"
                "  const busy = selectors.some((sel) => {"
                "    const nodes = Array.from(document.querySelectorAll(sel));"
                "    return nodes.some(isVisible);"
                "  });"
                "  return { state, busy };"
                "}",
                BUSY_INDICATOR_SELECTORS,
            ) or {}
            state = (status.get("state") or "").lower()
            busy = bool(status.get("busy"))
        except Exception:
            state = ""
            busy = False
        try:
            last_url = page.url or last_url
        except Exception:
            pass
        if state == "complete" and not busy:
            try:
                page.wait_for_load_state("networkidle", timeout=2000)
            except Exception:
                pass
            _log(f"{label} settled (state={state})")
            return True
        last_state = state
        last_busy = busy
        try:
            page.wait_for_timeout(500)
        except Exception:
            time.sleep(0.5)
        try:
            if page.is_closed():
                _log(f"{label} aborted (page closed)")
                return True
        except Exception:
            pass
            _log(
                f"{label} still loading after {total_timeout}ms (state={last_state} busy={last_busy} url={last_url})"
            )
    return False


def normalize_url(url: Optional[str]) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return url.strip()
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    normalized = parsed._replace(scheme=scheme, netloc=netloc, path=path).geturl()
    return normalized.rstrip("/") if normalized != "/" else normalized


def wait_for_url_change(
    page,
    previous_url: Optional[str],
    label: str,
    total_timeout: int = 30000,
) -> bool:
    baseline = normalize_url(previous_url)
    last_url = baseline
    deadline = time.time() + total_timeout / 1000.0
    while time.time() < deadline:
        try:
            current = normalize_url(page.url)
        except Exception:
            current = ""
        if current and baseline and current != baseline:
            _log(f"{label} url changed -> {current}")
            return True
        if current:
            last_url = current
        try:
            page.wait_for_timeout(500)
        except Exception:
            time.sleep(0.5)
        try:
            if page.is_closed():
                _log(f"{label} aborted while waiting for url change")
                return False
        except Exception:
            pass
    _log(
        f"{label} url unchanged after {total_timeout}ms (baseline={baseline or '<none>'} last={last_url or '<none>'})"
    )
    return False


def _parse_llm_json(resp: str, expected_keys: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    if not resp:
        return None

    def _try_load(text: str) -> Optional[Dict[str, Any]]:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if expected_keys:
                    return {k: obj.get(k) for k in expected_keys}
                return obj
        except Exception:
            return None
        return None

    obj = _try_load(resp)
    if obj is not None:
        return obj
    match = re.search(r"\{.*\}", resp, flags=re.S)
    if match:
        obj = _try_load(match.group(0))
        if obj is not None:
            return obj
    return None


def _ask_llm(
    prompt: str,
    expected_keys: Optional[List[str]] = None,
    chat_log_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    try:
        client = LLMClient()
        if chat_log_path:
            _append_login_chat(chat_log_path, "user", prompt)
        resp = client.chat([ChatMessage(role="user", content=prompt)], temperature=0, max_tokens=800)
        client.close()
        _log(f"llm raw reply: {resp[:500]}")
        if chat_log_path:
            _append_login_chat(chat_log_path, "assistant", resp)
        parsed = _parse_llm_json(resp, expected_keys=expected_keys)
        if parsed is None:
            raise ValueError(f"invalid json from llm: {resp[:200]}")
        return parsed
    except Exception as exc:
        if chat_log_path:
            _append_login_chat(chat_log_path, "assistant", f"<error: {exc}>")
        _log(f"llm call failed: {exc}")
        return None


def _llm_pick_login_button(
    buttons: List[Dict[str, Any]],
    purpose: str = "login",
    chat_log_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    if not buttons:
        return None
    purpose_desc = "登录" if purpose == "login" else "进入下一步"
    prompt = (
        "你是安全测试助手。下面是登录页上可见的按钮列表，请选择最可能用于"
        f"{purpose_desc}的按钮。"
        "严格输出 JSON，不能包含除 JSON 外的任何内容，不要加反引号、说明或前缀。"
        "格式: {\"button_index\": int}，若无法判断返回 {}。\n"
        f"按钮列表: {buttons}"
    )
    return _ask_llm(prompt, expected_keys=["button_index"], chat_log_path=chat_log_path)


def _llm_choose_fields(
    inputs: List[Dict[str, Any]],
    chat_log_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    if not inputs:
        return None
    prompt = (
        "你是安全测试助手。下面是页面上的输入字段列表，请选出最可能用于填写用户名和密码的字段。"
        "严格输出 JSON，不能包含除 JSON 外的任何内容，不要加反引号、说明或前缀。"
        "格式: {\"username_field_index\": int | null, \"password_field_index\": int | null}。"
        "若无法判断返回 {}。\n"
        f"字段列表: {inputs}"
    )
    return _ask_llm(
        prompt,
        expected_keys=["username_field_index", "password_field_index"],
        chat_log_path=chat_log_path,
    )


def _classify_login_scenario(user_visible: bool, pass_visible: bool) -> str:
    if user_visible and pass_visible:
        return "username_password"
    if user_visible and not pass_visible:
        return "username_then_password"
    if pass_visible and not user_visible:
        return "password_only"
    return "unknown"


def _refresh_field_entries(
    page,
    chat_log_path: Optional[Path],
) -> Tuple[
    Optional[Dict[str, Any]],
    Optional[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    inputs_info, input_entries = _collect_inputs(page)
    llm_fields = _llm_choose_fields(inputs_info, chat_log_path=chat_log_path)
    user_entry = None
    pass_entry = None
    if llm_fields:
        try:
            idx = llm_fields.get("username_field_index")
            if isinstance(idx, int):
                user_entry = next((e for e in input_entries if e["index"] == idx), None)
        except Exception:
            user_entry = None
        try:
            idx = llm_fields.get("password_field_index")
            if isinstance(idx, int):
                pass_entry = next((e for e in input_entries if e["index"] == idx), None)
        except Exception:
            pass_entry = None
        _log(
            f"LLM field selection -> user_index={llm_fields.get('username_field_index')} pass_index={llm_fields.get('password_field_index')}"
        )

    if user_entry and not user_entry.get("fillable"):
        _log(f"LLM user field {user_entry['descriptor']} not fillable, fallback")
        user_entry = None
    if pass_entry and not pass_entry.get("fillable"):
        _log(f"LLM password field {pass_entry['descriptor']} not fillable, fallback")
        pass_entry = None

    if user_entry is None:
        user_entry = next(
            (e for e in input_entries if e["fillable"] and e["visible"] and e["meta"]["type"] not in {"password", "hidden"}),
            None,
        )
    if pass_entry is None:
        pass_entry = next(
            (
                e
                for e in input_entries
                if e["fillable"]
                and e["visible"]
                and (
                    e["meta"].get("type") == "password"
                    or e["meta"].get("aria", "").lower().startswith("password")
                    or "password" in (e["meta"].get("name") or "").lower()
                )
            ),
            None,
        )
    return user_entry, pass_entry, input_entries


def _fill_entry(entry: Optional[Dict[str, Any]], value: str, label: str) -> bool:
    if not entry:
        _log(f"skip {label} (no entry)")
        return False
    if entry.get("disabled"):
        _log(f"skip {label} ({entry['descriptor']} disabled)")
        return False
    if not entry.get("fillable"):
        _log(f"skip {label} ({entry['descriptor']} not fillable)")
        return False
    try:
        handle = entry["handle"]
        handle.wait_for_element_state("visible", timeout=5000)
        handle.fill(value, timeout=5000)
        _log(f"filled {label} via {entry['descriptor']}")
        return True
    except Exception as exc:
        _log(f"fill {label} failed: {exc}")
        return False


def perform_login_interaction(
    page,
    login_username: Optional[str],
    login_password: Optional[str],
    chat_log_path: Optional[Path],
) -> LoginResult:
    user_entry, pass_entry, _ = _refresh_field_entries(page, chat_log_path)
    user_visible = bool(user_entry and user_entry.get("visible"))
    pass_visible = bool(pass_entry and pass_entry.get("visible"))
    login_scenario = _classify_login_scenario(user_visible, pass_visible)
    _log(
        f"字段选择结果： user={user_entry['descriptor'] if user_entry else '<none>'} pass={pass_entry['descriptor'] if pass_entry else '<none>'} 场景={login_scenario}"
    )

    password_filled = False
    if login_username is not None:
        _fill_entry(user_entry, login_username, "username")
    if login_password is not None and login_scenario != "username_then_password":
        password_filled = _fill_entry(pass_entry, login_password, "password")

    if login_username is not None and login_scenario == "username_then_password":
        if _click_stage_button(page, "next-step", chat_log_path):
            wait_for_page_idle(page, "next-step transition", total_timeout=25000)
            user_entry, pass_entry, _ = _refresh_field_entries(page, chat_log_path)
            user_visible = bool(user_entry and user_entry.get("visible"))
            pass_visible = bool(pass_entry and pass_entry.get("visible"))
            login_scenario = _classify_login_scenario(user_visible, pass_visible)
            _log(f"下一步后场景: {login_scenario}")
        else:
            _log("未找到下一步按钮，继续尝试登录按钮")

    if login_password is not None and not password_filled:
        password_filled = _fill_entry(pass_entry, login_password, "password")

    clicked_login = False
    pre_login_url = None
    if login_password is not None or login_username is not None:
        try:
            pre_login_url = page.url
        except Exception:
            pre_login_url = None
        clicked_login = _click_stage_button(page, "login", chat_log_path)
    return LoginResult(
        user_entry=user_entry,
        pass_entry=pass_entry,
        login_scenario=login_scenario,
        clicked_login=clicked_login,
        pre_login_url=pre_login_url,
    )


def _click_stage_button(page, purpose: str, chat_log_path: Optional[Path]) -> bool:
    buttons_info, button_entries = _collect_buttons(page)
    labels = [f"[{entry['index']}] {entry['label']} ({entry['descriptor']})" for entry in button_entries]
    if labels:
        _log(f"visible buttons ({purpose}): {labels}")
    return _click_button_with_strategy(
        button_entries,
        buttons_info,
        purpose,
        chat_log_path=chat_log_path,
    )
