# -*- coding: utf-8 -*-
"""
模块：配置与数据结构 (已修复)
- ScannerConfig: 统一管理扫描配置和Payloads
- ScanResult: 定义扫描结果的数据结构
"""
import os
import socket
import logging
from typing import List, Dict, Any, Tuple, Set

class ScannerConfig:
    """统一管理扫描配置和Payloads"""
    # 高风险参数（优先测试）
    HIGH_RISK_PARAMS = ["redirect_uri", "next", "redirect", "return_url", "target", "dest", "goto", "returnTo", "callback_url"]
    
    # 参数黑名单（跳过测试）
    PARAM_BLACKLIST = ["callback", "jsoncallback", "success", "error", "notify_url", "sign", "token", "auth", "session", "key"]
    
    REDIRECT_PARAM_NAMES: List[str] = sorted(list(set([
        "aff", "affiliate", "auth", "authentication_return_to", "bounce", "callback", "callbackURL", "callback_url", "cb", "cgi-bin/redirect.cgi", "checkout", "checkout_url", "client_id", "continue", "continueTo", "continue_url", "context", "data", "dest", "destination", "dest_url", "display", "domain", "done", "end_url", "error", "error_url", "exit_url", "fail", "failure_url", "fav", "feedback", "file", "finish", "forward", "forward_url", "from", "from_url", "go", "go_to", "goto", "guest", "href", "id", "image_url", "inurl", "jump", "jump_to", "lang", "language", "link", "load", "load_file", "load_url", "local", "locale", "location", "login", "login_redirect", "login_url", "logout", "logout_redirect_url", "loop", "media", "message", "nav", "navigation", "next", "nextUrl", "next_page", "next_url", "next-url", "next_uri", "on_error", "on_failure", "on_login", "on_logout", "on_success", "out", "page", "page_url", "page_to", "path", "port", "portal", "prev_page", "r", "redir", "redirect", "Redirect", "redirect-after-login", "redirect.php", "redirect_after_login", "redirect_to", "redirect_url", "redirect_uri", "redirect-url", "redirectUrl", "RedirectUrl", "RedirectURL", "referrer", "ref", "referer", "RelayState", "req", "request", "request_uri", "res", "resource", "ret", "return", "Return", "returnTo", "return_page", "return_path", "return_to", "return_url", "ReturnUrl", "ReturnURL", "return-url", "r_url", "rurl", "SAMLRequest", "site", "sso", "start_url", "success_url", "s_url", "target", "to", "trace", "u", "uri", "url", "URL", "Url", "val", "validate", "view", "window"
    ])))
    
    # 错误行已从此位置移除

    REDIRECT_COMMON_PATHS: List[str] = sorted(list(set(["/login", "/logout", "/auth", "/oauth", "/redirect"])))
    
    # 开放重定向Payload模板
    REDIRECT_PAYLOAD_TEMPLATES: List[str] = [
        # 基础Payload
        "https://{host}", "http://{host}",
        # 协议相关绕过
        "//{host}", "/\\/{host}", "\\/{host}", "https:{host}",
        # 利用@符号
        "https://trusted.com@{host}", "{target_domain}@{host}",
        # 利用URL编码
        "https://www%2e{domain_part}%2e{tld_part}", "https%3A//{host}", "https://{host}/%2e%2e%2f",
        # 利用特殊字符
        "https://{host}?key=val", "https://{host}#fragment", "?{host}", "#{host}",
        # 利用CRLF (换行符)
        "/%0a{host}", "/%0d{host}",
        # 利用data URI实现XSS
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        # 利用javascript协议
        "javascript:alert(document.domain)", "javascript://%250Aalert(1)",
        # 空格和制表符
        " https://{host}", "\t//{host}",
    ]
    
    CONTEXT_AWARE_TEMPLATES: List[str] = [
        "https://{payload_host}.{target_domain}", 
        "https://{target_domain}.{payload_host}",
        "https://{payload_host}?origin={target_domain}",
        "//{payload_host}/?ref={target_domain}",
    ]

    USER_AGENTS: List[str] = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"]
    FUZZ_PATHS_FILE = "custom_paths.txt"

    def __init__(self, payload_host: str):
        self.payload_host = payload_host
        self.payload_domain = '.'.join(payload_host.split('.')[-2:])
        self.payload_domain_part = payload_host.split('.')[1] if '.' in payload_host else payload_host
        self.payload_tld_part = payload_host.split('.')[-1] if '.' in payload_host else ''
        self._resolved_ip = None

    def get_payloads_for_target(self, target_domain: str) -> List[Tuple[str, str]]:
        payloads = set()
        for template in self.REDIRECT_PAYLOAD_TEMPLATES:
            try:
                payload = template.format(
                    host=self.payload_host, 
                    domain_part=self.payload_domain_part, 
                    tld_part=self.payload_tld_part,
                    target_domain=target_domain
                )
                payloads.add((payload, self.payload_domain))
            except (KeyError, IndexError): pass
        
        for template in self.CONTEXT_AWARE_TEMPLATES:
            try:
                payload = template.format(payload_host=self.payload_host, target_domain=target_domain)
                payloads.add((payload, self.payload_domain))
            except KeyError: pass
        
        normalized_payloads = {p.strip(): (p, pattern) for p, pattern in payloads}
        return list(normalized_payloads.values())

    def load_custom_paths(self) -> List[str]:
        if os.path.exists(self.FUZZ_PATHS_FILE):
            try:
                with open(self.FUZZ_PATHS_FILE, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logging.warning(f"加载自定义路径失败: {e}")
        return []
    
    def get_resolved_ip(self) -> str:
        if not self._resolved_ip:
            try:
                self._resolved_ip = socket.gethostbyname(self.payload_host)
            except socket.gaierror: self._resolved_ip = "unknown"
        return self._resolved_ip

class ScanResult:
    def __init__(self, method: str, url: str, payload: str, evidence: str, target: str, param_name: str):
        self.target, self.method, self.url, self.payload, self.evidence, self.param_name = target, method, url, payload, evidence, param_name
        self.severity = self._calculate_severity()
        self.vulnerability_key = (method, url, payload, param_name)

    def _calculate_severity(self) -> str:
        evidence_lower = self.evidence.lower()
        if 'javascript:' in evidence_lower or 'data:' in evidence_lower:
            return "CRITICAL"
        if self.evidence.startswith(('//', '/\\/', '\\/')) or any(x in evidence_lower for x in ['%0a', '%0d', '..']):
            return "HIGH"
        if '@' in evidence_lower:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        result = self.__dict__.copy()
        result['remediation'] = "Validate and sanitize all redirect URLs. Implement allowlist-based validation for redirect targets."
        return result

# --- 修复 NameError ---
# 在类完全定义后应用黑名单过滤器，以解决作用域问题。
ScannerConfig.REDIRECT_PARAM_NAMES = [
    p for p in ScannerConfig.REDIRECT_PARAM_NAMES 
    if p.lower() not in ScannerConfig.PARAM_BLACKLIST
]
