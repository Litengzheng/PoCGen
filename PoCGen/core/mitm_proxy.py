from __future__ import annotations
import re
import json
from typing import Dict, Any, Optional, Callable
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster
import threading
import time


class MITMProxy:
    """中间人代理，用于拦截和修改HTTP请求/响应"""
    
    def __init__(self, listen_port: int = 8080):
        self.listen_port = listen_port
        self.proxy = None
        self.thread = None
        self.modification_rules = []
        self.captured_requests = []
        self.captured_responses = []
    
    def add_modification_rule(self, rule: Dict[str, Any]):
        """添加修改规则"""
        self.modification_rules.append(rule)
    
    def clear_rules(self):
        """清除所有规则"""
        self.modification_rules.clear()
    
    def start(self):
        """启动代理服务器"""
        opts = options.Options(
            listen_port=self.listen_port,
            mode="regular"
        )
        
        self.proxy = DumpMaster(opts)
        
        # 添加处理程序
        self.proxy.addons.add(self)
        
        # 在后台线程中运行代理
        self.thread = threading.Thread(target=self._run_proxy)
        self.thread.daemon = True
        self.thread.start()
        
        time.sleep(2)  # 等待代理启动
    
    def stop(self):
        """停止代理服务器"""
        if self.proxy:
            self.proxy.shutdown()
        if self.thread:
            self.thread.join(timeout=5)
    
    def _run_proxy(self):
        """运行代理服务器"""
        try:
            self.proxy.run()
        except Exception as e:
            print(f"Proxy error: {e}")
    
    def request(self, flow: http.HTTPFlow):
        """拦截请求"""
        # 记录请求
        request_info = {
            "url": flow.request.url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "timestamp": time.time()
        }
        self.captured_requests.append(request_info)
        
        # 应用修改规则
        for rule in self.modification_rules:
            if self._should_modify(flow.request, rule):
                self._apply_modification(flow.request, rule)
    
    def response(self, flow: http.HTTPFlow):
        """拦截响应"""
        # 记录响应
        response_info = {
            "url": flow.request.url,
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.text,
            "timestamp": time.time()
        }
        self.captured_responses.append(response_info)
        
        # 应用响应修改规则
        for rule in self.modification_rules:
            if rule.get("type") == "response" and self._should_modify(flow.request, rule):
                self._apply_response_modification(flow.response, rule)
    
    def _should_modify(self, request: http.Request, rule: Dict) -> bool:
        """判断是否应该修改此请求"""
        url_pattern = rule.get("match", {}).get("url_pattern", ".*")
        method = rule.get("match", {}).get("method")
        
        if not re.match(url_pattern, request.url):
            return False
        
        if method and method != request.method:
            return False
        
        return True
    
    def _apply_modification(self, request: http.Request, rule: Dict):
        """应用请求修改"""
        rule_type = rule.get("type")
        action = rule.get("action", "set")
        key = rule.get("key")
        value = rule.get("value")
        
        if rule_type == "header" and key:
            if action == "set":
                request.headers[key] = value
            elif action == "append":
                if key in request.headers:
                    request.headers[key] += f", {value}"
                else:
                    request.headers[key] = value
        
        elif rule_type == "param":
            # 修改查询参数
            pass
        
        elif rule_type == "body" and request.method in ["POST", "PUT"]:
            # 修改请求体
            pass
    
    def _apply_response_modification(self, response: http.Response, rule: Dict):
        """应用响应修改"""
        action = rule.get("action", "inject")
        xss_payload = rule.get("payload", "<script>alert('XSS')</script>")
        
        if action == "inject":
            # 在响应体中注入XSS payload
            original_body = response.text
            modified_body = self._inject_xss_payload(original_body, xss_payload)
            response.text = modified_body
    
    def _inject_xss_payload(self, html: str, payload: str) -> str:
        """在HTML中注入XSS payload"""
        # 简单的注入策略：在body结束前注入
        if "</body>" in html.lower():
            return html.replace("</body>", f"{payload}</body>")
        else:
            return html + payload
    
    def get_proxy_url(self) -> str:
        """获取代理URL"""
        return f"http://127.0.0.1:{self.listen_port}"