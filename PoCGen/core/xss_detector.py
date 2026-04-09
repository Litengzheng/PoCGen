from __future__ import annotations
import re
from typing import Tuple, Optional
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


class XSSDetector:
    def __init__(self, headless: bool = True, timeout: int = 10000):
        self.headless = headless
        self.timeout = timeout
        self.playwright = None
        self.browser = None
        self.context = None
    
    def __enter__(self):
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        self.context = self.browser.new_context(
            ignore_https_errors=True,
            viewport={'width': 1280, 'height': 720}
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def detect_xss(self, url: str, response_body: str = "") -> Tuple[bool, str]:
        """
        检测给定URL或响应体中是否存在XSS漏洞
        返回: (是否发现XSS, 描述信息)
        """
        if not self.context:
            self.__enter__()
        
        page = self.context.new_page()
        
        # 设置页面处理alert对话框
        alert_triggered = False
        alert_message = ""
        
        def handle_dialog(dialog):
            nonlocal alert_triggered, alert_message
            alert_triggered = True
            alert_message = dialog.message
            dialog.dismiss()
        
        page.on("dialog", handle_dialog)
        
        try:
            # 如果有响应体，直接设置内容
            if response_body:
                page.set_content(response_body, timeout=self.timeout)
            else:
                # 否则访问URL
                page.goto(url, timeout=self.timeout, wait_until="networkidle")
            
            # 等待一小段时间让JavaScript执行
            page.wait_for_timeout(2000)
            
            # 检查响应中是否包含常见的XSS payload模式
            html_content = page.content()
            
            # 检查是否触发alert
            if alert_triggered:
                return True, f"Alert triggered with message: '{alert_message}'"
            
            # 检查响应中是否包含未转义的payload
            xss_patterns = [
                r'<svg[^>]*onload\s*=',
                r'<img[^>]*onerror\s*=',
                r'<script[^>]*>.*alert.*</script>',
                r'onload\s*=\s*["\']?alert',
                r'onerror\s*=\s*["\']?alert',
                r'onclick\s*=\s*["\']?alert',
                r'onmouseover\s*=\s*["\']?alert',
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    return True, f"XSS pattern found in response: {pattern}"
            
            # 检查事件处理程序
            event_handlers = page.evaluate("""
                () => {
                    const elementsWithEvents = [];
                    const events = ['onload', 'onerror', 'onclick', 'onmouseover'];
                    
                    events.forEach(event => {
                        document.querySelectorAll(`[${event}]`).forEach(el => {
                            elementsWithEvents.push({
                                tag: el.tagName,
                                event: event,
                                handler: el.getAttribute(event)
                            });
                        });
                    });
                    
                    return elementsWithEvents;
                }
            """)
            
            if event_handlers:
                for element in event_handlers:
                    if 'alert' in element['handler']:
                        return True, f"Alert found in {element['tag']} {element['event']} handler"
            
            return False, "No XSS detected"
            
        except PlaywrightTimeoutError:
            return False, "Timeout while loading page"
        except Exception as e:
            return False, f"Error during XSS detection: {str(e)}"
        finally:
            page.close()
    
    def close(self):
        """清理资源"""
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()




# from __future__ import annotations
# import re
# import json
# from typing import Tuple, Optional, Dict, Any, List
# from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError, Request, Response


# class XSSDetector:
#     def __init__(self, headless: bool = True, timeout: int = 10000):
#         self.headless = headless
#         self.timeout = timeout
#         self.playwright = None
#         self.browser = None
#         self.context = None
#         self.page = None
#         self.intercepted_requests: List[Dict] = []
    
#     def __enter__(self):
#         self.playwright = sync_playwright().start()
#         self.browser = self.playwright.chromium.launch(headless=self.headless)
#         self.context = self.browser.new_context(
#             ignore_https_errors=True,
#             viewport={'width': 1280, 'height': 720}
#         )
#         return self
    
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         self.close()
    
#     def _setup_request_interception(self, page):
#         """设置请求拦截，用于修改请求"""
#         page.route("**/*", self._request_interceptor)
    
#     def _request_interceptor(self, route: Request, request: Request):
#         """请求拦截器回调函数"""
#         # 记录原始请求
#         request_info = {
#             "url": request.url,
#             "method": request.method,
#             "headers": request.headers,
#             "post_data": request.post_data,
#             "timestamp": datetime.now().isoformat()
#         }
#         self.intercepted_requests.append(request_info)
        
#         # 在这里可以修改请求
#         # 例如，修改请求头、参数、请求体等
        
#         # 继续请求
#         route.continue_()
    
#     def detect_xss(self, url: str, response_body: str = "") -> Tuple[bool, str]:
#         """
#         基本XSS检测 - 直接访问URL或设置响应体
#         """
#         if not self.context:
#             self.__enter__()
        
#         self.page = self.context.new_page()
        
#         # 设置请求拦截
#         self._setup_request_interception(self.page)
        
#         # 设置页面处理alert对话框
#         alert_triggered = False
#         alert_message = ""
        
#         def handle_dialog(dialog):
#             nonlocal alert_triggered, alert_message
#             alert_triggered = True
#             alert_message = dialog.message
#             dialog.dismiss()
        
#         self.page.on("dialog", handle_dialog)
        
#         try:
#             if response_body:
#                 self.page.set_content(response_body, timeout=self.timeout)
#             else:
#                 self.page.goto(url, timeout=self.timeout, wait_until="networkidle")
            
#             self.page.wait_for_timeout(2000)
            
#             if alert_triggered:
#                 return True, f"Alert triggered with message: '{alert_message}'"
            
#             return False, "No XSS detected"
            
#         except PlaywrightTimeoutError:
#             return False, "Timeout while loading page"
#         except Exception as e:
#             return False, f"Error during XSS detection: {str(e)}"
#         finally:
#             if self.page:
#                 self.page.close()
#                 self.page = None
    
#     def detect_xss_with_request_modification(
#         self, 
#         url: str, 
#         modify_rules: Optional[List[Dict[str, Any]]] = None
#     ) -> Tuple[bool, str, List[Dict]]:
#         """
#         高级XSS检测 - 支持请求/响应修改
        
#         Args:
#             url: 目标URL
#             modify_rules: 修改规则列表，每个规则格式:
#                 {
#                     "type": "header" | "param" | "body" | "response",
#                     "match": {"url_pattern": ".*", "method": "GET"},
#                     "action": "set" | "append" | "replace",
#                     "key": "header_name" | "param_name" | "body_field",
#                     "value": "new_value"
#                 }
#         """
#         if not self.context:
#             self.__enter__()
        
#         self.page = self.context.new_page()
#         self.intercepted_requests = []
        
#         # 设置请求拦截
#         alert_triggered = False
#         alert_message = ""
        
#         def handle_dialog(dialog):
#             nonlocal alert_triggered, alert_message
#             alert_triggered = True
#             alert_message = dialog.message
#             dialog.dismiss()
        
#         self.page.on("dialog", handle_dialog)
        
#         def route_handler(route: Request, request: Request):
#             """自定义路由处理器，支持修改请求"""
#             # 检查是否需要修改此请求
#             should_modify = False
#             modifications = {}
            
#             if modify_rules:
#                 for rule in modify_rules:
#                     # 检查URL匹配
#                     url_pattern = rule.get("match", {}).get("url_pattern", ".*")
#                     if not re.match(url_pattern, request.url):
#                         continue
                    
#                     # 检查方法匹配
#                     method = rule.get("match", {}).get("method")
#                     if method and method != request.method:
#                         continue
                    
#                     should_modify = True
#                     rule_type = rule.get("type")
                    
#                     if rule_type == "header":
#                         headers = request.headers.copy()
#                         headers[rule["key"]] = rule["value"]
#                         modifications["headers"] = headers
                    
#                     elif rule_type == "param":
#                         # 修改URL参数
#                         # 这里需要解析URL并修改参数
#                         pass
                    
#                     elif rule_type == "body" and request.method == "POST":
#                         # 修改请求体
#                         post_data = request.post_data
#                         if post_data:
#                             # 尝试解析为JSON或表单数据
#                             try:
#                                 data = json.loads(post_data)
#                                 data[rule["key"]] = rule["value"]
#                                 modifications["post_data"] = json.dumps(data)
#                             except:
#                                 # 如果不是JSON，可能是表单数据
#                                 modifications["post_data"] = f"{post_data}&{rule['key']}={rule['value']}"
            
#             if should_modify:
#                 # 应用修改
#                 route.continue_(**modifications)
#             else:
#                 route.continue_()
        
#         # 设置路由拦截
#         self.page.route("**/*", route_handler)
        
#         try:
#             self.page.goto(url, timeout=self.timeout, wait_until="networkidle")
#             self.page.wait_for_timeout(3000)
            
#             # 检查DOM中的脚本执行
#             html_content = self.page.content()
            
#             # 检查是否有恶意脚本执行
#             malicious_patterns = [
#                 r'<script[^>]*>.*alert.*</script>',
#                 r'javascript:alert',
#                 r'onload\s*=\s*["\']?alert',
#                 r'onerror\s*=\s*["\']?alert',
#                 r'onclick\s*=\s*["\']?alert',
#             ]
            
#             for pattern in malicious_patterns:
#                 if re.search(pattern, html_content, re.IGNORECASE):
#                     return True, f"Malicious script pattern found: {pattern}", self.intercepted_requests
            
#             if alert_triggered:
#                 return True, f"Alert triggered: {alert_message}", self.intercepted_requests
            
#             return False, "No XSS detected after request modification", self.intercepted_requests
            
#         except Exception as e:
#             return False, f"Error: {str(e)}", self.intercepted_requests
#         finally:
#             if self.page:
#                 self.page.close()
#                 self.page = None
    
#     def detect_xss_with_response_modification(
#         self, 
#         url: str, 
#         response_modifier: callable
#     ) -> Tuple[bool, str]:
#         """
#         支持响应修改的XSS检测
        
#         Args:
#             url: 目标URL
#             response_modifier: 函数，接收原始响应，返回修改后的响应
#         """
#         if not self.context:
#             self.__enter__()
        
#         self.page = self.context.new_page()
        
#         alert_triggered = False
#         alert_message = ""
        
#         def handle_dialog(dialog):
#             nonlocal alert_triggered, alert_message
#             alert_triggered = True
#             alert_message = dialog.message
#             dialog.dismiss()
        
#         self.page.on("dialog", handle_dialog)
        
#         def route_handler(route: Request, request: Request):
#             """拦截并修改响应"""
#             response = route.fetch()
            
#             # 获取原始响应
#             original_body = response.text()
            
#             # 应用修改
#             modified_body = response_modifier(original_body)
            
#             # 返回修改后的响应
#             route.fulfill(
#                 response=response,
#                 body=modified_body
#             )
        
#         # 拦截所有响应
#         self.page.route("**/*", route_handler)
        
#         try:
#             self.page.goto(url, timeout=self.timeout, wait_until="networkidle")
#             self.page.wait_for_timeout(2000)
            
#             if alert_triggered:
#                 return True, f"Alert triggered: {alert_message}"
            
#             return False, "No XSS detected after response modification"
            
#         except Exception as e:
#             return False, f"Error: {str(e)}"
#         finally:
#             if self.page:
#                 self.page.close()
#                 self.page = None
    
#     def close(self):
#         """清理资源"""
#         if self.page:
#             self.page.close()
#         if self.context:
#             self.context.close()
#         if self.browser:
#             self.browser.close()
#         if self.playwright:
#             self.playwright.stop()