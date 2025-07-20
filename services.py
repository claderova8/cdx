# -*- coding: utf-8 -*-
"""
模块：辅助服务
- WAFDetector: 检测目标是否存在WAF/CDN
- SecretFinder: 通过分析JS/HTML发现隐藏参数
- PreflightChecker: 执行预检，判断目标是否值得扫描
"""
import asyncio
import aiohttp
import re
import logging
import urllib.parse
from typing import Optional, Set

class WAFDetector:
    # 增强WAF检测签名
    WAF_SIGNATURES = {
        'Cloudflare': [('Server', r'cloudflare'), ('CF-RAY', r'.+')],
        'Akamai': [('Server', r'AkamaiGHost'), ('X-Akamai-Transformed', r'.+')],
        'Imperva': [('X-Iinfo', r'.+'), ('X-CDN', r'Imperva')],
        'AWS WAF': [('Server', r'awselb'), ('x-amz-request-id', r'.+')],
        'Sucuri': [('Server', r'Sucuri/Cloudproxy'), ('X-Sucuri-ID', r'.+')],
        'F5 BIG-IP': [('Server', r'BigIP|BIG-IP'), ('X-F5-TM', r'.+')],
        'Fortinet': [('Server', r'FortiWeb'), ('X-FortiWeb', r'.+')]
    }
    
    # 添加内容签名
    CONTENT_SIGNATURES = {
        'Cloudflare': re.compile(r'<title>Access Denied</title>.*?Cloudflare', re.DOTALL | re.IGNORECASE),
        'Akamai': re.compile(r'akamai\serror', re.IGNORECASE),
        'Imperva': re.compile(r'<title>imperva</title>', re.IGNORECASE),
        'AWS WAF': re.compile(r'<RequestId>[^<]+</RequestId>', re.IGNORECASE),
    }

    async def detect(self, session: aiohttp.ClientSession, target_url: str) -> Optional[str]:
        try:
            # 1. 正常请求检测
            async with session.get(target_url, timeout=5, allow_redirects=False) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                content = await resp.text()
                
                # 检查头部特征
                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    if all(re.search(pattern, headers.get(h.lower(), ''), re.IGNORECASE) for h, pattern in signatures):
                        return waf_name
                
                # 检查内容特征
                for waf_name, pattern in self.CONTENT_SIGNATURES.items():
                    if pattern.search(content):
                        return waf_name
                        
            # 2. 异常触发测试
            malformed_url = target_url + "'%22><"
            async with session.get(malformed_url, timeout=2) as resp:
                content = await resp.text()
                
                # 检测WAF特定错误页面
                for waf_name, pattern in self.CONTENT_SIGNATURES.items():
                    if pattern.search(content):
                        return waf_name
                        
        except Exception as e:
            logging.debug(f"WAF检测失败: {e}")
            return None
        return None

class SecretFinder:
    """通过分析JS文件发现隐藏参数的服务 (高级增强版)"""
    KEYWORD_LIST = "(?:next|redirect|goto|return|dest|callback|url|uri|path|page|location|continue|to|from|out)"
    
    # 增强正则表达式
    REGEX_LIST = [
        re.compile(r'["\']([a-zA-Z0-9_.-]*?' + KEYWORD_LIST + r'[a-zA-Z0-9_.-]*?)["\']\s*:'),
        re.compile(r'\b([a-zA-Z0-9_.-]*?' + KEYWORD_LIST + r'[a-zA-Z0-9_.-]*?)\s*=\s*["\']'),
        re.compile(r'[?&]([a-zA-Z0-9_.-]*?' + KEYWORD_LIST + r'[a-zA-Z0-9_.-]*?)='),
        # 新增：检测JS变量声明
        re.compile(r'(?:var|let|const)\s+([a-zA-Z0-9_]*?' + KEYWORD_LIST + r'[a-zA-Z0-9_]*?)\s*='),
        # 新增：检测AJAX请求参数
        re.compile(r'\.(get|post|put|delete)\([^)]*?[\'"]([a-zA-Z0-9_]*?' + KEYWORD_LIST + r'[a-zA-Z0-9_]*?)='),
        # 新增：检测表单字段
        re.compile(r'<input[^>]+name=["\']([a-zA-Z0-9_]*?' + KEYWORD_LIST + r'[a-zA-Z0-9_]*?)["\']')
    ]
    
    GENERIC_TERMS = {"url", "uri", "path", "page", "location", "domain", "host", "to", "from", "out"}
    NEGATIVE_KEYWORDS = {"token", "csrf", "session", "key", "auth", "nonce", "secret", "password", "signature"}
    KEYWORDS = {"redirect", "goto", "next", "return", "callback", "continue", "target", "dest", "location"}

    def _score_param(self, param: str) -> int:
        """为参数名评分"""
        score = 0
        param_lower = param.lower()
        
        # 正面评分
        if any(kw in param_lower for kw in self.KEYWORDS):
            score += 2
        if len(param) > 5 and len(param) < 25:
            score += 1
        if '.' in param or '_' in param:  # 复合参数名
            score += 1
            
        # 负面评分
        if any(neg_kw in param_lower for neg_kw in self.NEGATIVE_KEYWORDS):
            score -= 3  # 增加负权重
        if param_lower in self.GENERIC_TERMS:
            score -= 1
            
        return score

    async def _analyze_content(self, content: str) -> Set[str]:
        found_secrets = set()
        for regex in self.REGEX_LIST:
            for match in regex.findall(content):
                # 处理可能有多个捕获组的正则
                if isinstance(match, tuple):
                    for item in match:
                        if item: found_secrets.add(item)
                elif match:
                    found_secrets.add(match)
        return found_secrets

    async def find(self, session: aiohttp.ClientSession, target_url: str, C) -> Set[str]:
        all_secrets = set()
        try:
            async with session.get(target_url, timeout=10) as resp:
                if 'text/html' not in resp.headers.get('Content-Type', ''): 
                    return set()
                body = await resp.text()

            # 分析主HTML内容
            all_secrets.update(await self._analyze_content(body))
            
            # 分析内联JS
            inline_js_contents = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
            for content in inline_js_contents:
                all_secrets.update(await self._analyze_content(content))
            
            # 分析外部JS
            external_js_urls = {urllib.parse.urljoin(target_url, path) for path in re.findall(r'<script[^>]+src=["\'](.+?)["\']', body)}
            js_tasks = [self._fetch_and_analyze_js(session, url, C) for url in external_js_urls]
            for secrets_from_js in await asyncio.gather(*js_tasks):
                all_secrets.update(secrets_from_js)
                
        except Exception as e:
            logging.debug(f"发现秘密参数时出错 {target_url}: {e}")
        
        # 使用评分系统过滤参数 - 提高阈值到4
        filtered_secrets = set()
        for secret in all_secrets:
            if self._score_param(secret) >= 4:  # 评分阈值提高到4
                filtered_secrets.add(secret)
                
        return filtered_secrets

    async def _fetch_and_analyze_js(self, session: aiohttp.ClientSession, url: str, C) -> Set[str]:
        found_secrets = set()
        try:
            # 1. 检查Source Map
            sourcemap_url = url + ".map"
            async with session.get(sourcemap_url, timeout=10) as resp:
                if resp.status == 200:
                    sourcemap_data = await resp.json()
                    if 'sourcesContent' in sourcemap_data and sourcemap_data['sourcesContent']:
                        logging.info(f"[{C.GREEN}发现Source Map{C.ENDC}] {sourcemap_url}")
                        for content in sourcemap_data['sourcesContent']:
                            if content: found_secrets.update(await self._analyze_content(content))
            
            # 2. 获取JS内容
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    js_content = await resp.text()
                    found_secrets.update(await self._analyze_content(js_content))
        except Exception as e:
            logging.debug(f"获取或分析JS失败 {url}: {e}")
        return found_secrets

class PreflightChecker:
    """执行预检扫描，判断目标是否值得进行全面扫描"""
    async def is_scannable(self, session: aiohttp.ClientSession, target_url: str, C) -> bool:
        """检查Content-Type是否为HTML"""
        try:
            async with session.head(target_url, timeout=5, allow_redirects=True) as resp:
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    return True
                logging.info(f"[{C.YELLOW}跳过{C.ENDC}] {target_url} (Content-Type: {content_type})")
                return False
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return True  # 如果HEAD请求失败，则保守地认为可以扫描
        except Exception as e:
            logging.debug(f"预检扫描失败 {target_url}: {e}")
            return True
