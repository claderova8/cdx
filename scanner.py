# -*- coding: utf-8 -*-
"""
模块：核心扫描引擎 (已修复统计Bug)
- TargetScanner: 对单个目标执行所有网络请求和漏洞检测逻辑
"""
import asyncio
import aiohttp
import urllib.parse
import time
import logging
import random
import re
import sys
import argparse
from collections import defaultdict
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

# 导入依赖
from config import ScannerConfig, ScanResult
from ui import C

@dataclass
class ScanContext:
    """封装扫描会话的共享资源"""
    args: argparse.Namespace
    session: aiohttp.ClientSession
    config: ScannerConfig
    services: 'Services'

class TargetScanner:
    """执行单个目标的异步开放重定向扫描"""
    def __init__(self, target_url: str, context: ScanContext, extra_params: Set[str] = None):
        self.target_url, self.context, self.extra_params = target_url, context, extra_params or set()
        self.args = context.args
        self.config = context.config
        self.session = context.session
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{self.parsed_url.path}"
        self.orig_params = urllib.parse.parse_qs(self.parsed_url.query, keep_blank_values=True)
        self.netloc = self.parsed_url.netloc
        self.timeout = aiohttp.ClientTimeout(total=self.args.timeout)
        self.semaphore = asyncio.Semaphore(self.args.concurrency)
        self.results: Dict[tuple, ScanResult] = {}
        self.errors = defaultdict(int)
        self.start_time = time.time()
        self.csrf_tokens: Dict[str, str] = {}
        self.total_requests = 0 # 初始化请求计数器

    def _generate_tasks(self) -> List[Dict[str, Any]]:
        tasks: List[Dict[str, Any]] = []
        if self.orig_params:
            param_source = list(self.orig_params.keys())
        else:
            param_source = self.config.REDIRECT_PARAM_NAMES

        def param_score(param):
            score = 0
            param_lower = param.lower()
            if param_lower in [p.lower() for p in ScannerConfig.HIGH_RISK_PARAMS]: score += 10
            if any(kw in param_lower for kw in {"redirect", "url", "goto", "return"}): score += 5
            return score
        
        param_source = sorted(param_source, key=param_score, reverse=True)
        max_params = min(self.args.max_params_per_target, len(param_source))
        param_source = param_source[:max_params]
        
        payloads = self.config.get_payloads_for_target(self.netloc)
        
        for param_name in param_source:
            for payload, pattern in payloads:
                get_params = {**self.orig_params, param_name: [payload]}
                get_qs = urllib.parse.urlencode(get_params, doseq=True)
                get_url = f"{self.base_url}?{get_qs}"
                tasks.append({'method': 'GET', 'url': get_url, 'payload': payload, 'pattern': pattern, 'param_name': param_name})
        return tasks

    async def _fetch(self, task: Dict[str, Any]) -> Optional[ScanResult]:
        self.total_requests += 1 # <--- 修复: 确保每个任务都计数
        m, u, p, pattern, param_name = task['method'], task['url'], task.get('payload'), task.get('pattern'), task.get('param_name')
        
        headers = {'User-Agent': random.choice(self.config.USER_AGENTS), 'Referer': self.base_url}
        req_kwargs: Dict[str, Any] = {'timeout': self.timeout, 'allow_redirects': False, 'headers': headers}
        
        try:
            async with self.semaphore:
                async with self.session.request(m, u, **req_kwargs) as resp:
                    if 300 <= resp.status < 400:
                        location_header = resp.headers.get('Location', '')
                        if location_header and (pattern in location_header or any(location_header.startswith(prefix) for prefix in ['//', '/\\', '\\/'])):
                            return ScanResult(m, u, p, location_header, self.target_url, param_name)
                    
                    if resp.status == 200 and 'text/html' in resp.headers.get('Content-Type', '').lower():
                        body = await resp.text(encoding='utf-8', errors='ignore')
                        body = body[:10240]
                        
                        js_redirect_url = self._detect_js_redirect(body, pattern)
                        if js_redirect_url: return ScanResult(m, u, p, js_redirect_url, self.target_url, param_name)
                        
                        meta_redirect_url = self._detect_meta_redirect(body, pattern)
                        if meta_redirect_url: return ScanResult(m, u, p, meta_redirect_url, self.target_url, param_name)
        except Exception as e:
            self.errors[type(e).__name__] += 1
            logging.debug(f"请求失败 {u}: {e}")
        return None
        
    def _detect_js_redirect(self, body: str, pattern: str) -> Optional[str]:
        js_patterns = [r'location\.href\s*=\s*["\'](.*?)["\']', r'window\.location\s*=\s*["\'](.*?)["\']']
        for regex in js_patterns:
            match = re.search(regex, body, re.IGNORECASE)
            if match:
                redirect_url = match.group(1).strip()
                if pattern in redirect_url: return redirect_url
        return None

    def _detect_meta_redirect(self, body: str, pattern: str) -> Optional[str]:
        meta_patterns = [r'<meta\s+http-equiv\s*=\s*["\']?refresh["\']?\s+content\s*=\s*["\']?\d+;\s*url=(.*?)["\'>]']
        for regex in meta_patterns:
            match = re.search(regex, body, re.IGNORECASE)
            if match:
                redirect_url = match.group(1).strip()
                if pattern in redirect_url: return redirect_url
        return None

    async def run(self) -> List[ScanResult]:
        tasks = self._generate_tasks()
        if not tasks: return []
        
        futures = [asyncio.create_task(self._fetch(t)) for t in tasks]
        
        # 优化点: 使用一个临时的set来跟踪已报告的漏洞，避免重复
        all_findings: List[ScanResult] = []

        try:
            from tqdm import tqdm
            pbar = tqdm(total=len(futures), desc=f'扫描 {self.netloc[:25]:<25}', leave=False, 
                        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
                        file=sys.stdout, colour='green')
            
            for fut in asyncio.as_completed(futures):
                try:
                    result = await fut
                    if result:
                        all_findings.append(result)
                except asyncio.CancelledError: pass
                finally: pbar.update(1)
            pbar.close()
        except (ImportError, ModuleNotFoundError): 
            for fut in asyncio.as_completed(futures):
                result = await fut
                if result:
                    all_findings.append(result)
        
        # 优化点: 对所有发现进行去重，只保留每个参数的最高风险漏洞
        best_results_per_param: Dict[str, ScanResult] = {}
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for finding in all_findings:
            param = finding.param_name
            current_severity_score = severity_order.get(finding.severity, 0)
            
            if param not in best_results_per_param or \
               current_severity_score > severity_order.get(best_results_per_param[param].severity, 0):
                best_results_per_param[param] = finding
        
        # 将去重和优选后的结果存入self.results
        for result in best_results_per_param.values():
            if result.vulnerability_key not in self.results:
                self.results[result.vulnerability_key] = result

        return list(self.results.values())
