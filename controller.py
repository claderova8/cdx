# -*- coding: utf-8 -*-
"""
模块：流程控制器 (已修复)
- ScanController: 管理整个扫描会话，编排工作流
"""
import asyncio
import aiohttp
import urllib.parse
import time
import logging
import platform
import resource
import sys
from collections import defaultdict
from typing import List, Set, ForwardRef
from dataclasses import dataclass # <--- 修复: 导入dataclass

# 导入项目模块
from config import ScannerConfig
from services import WAFDetector, SecretFinder, PreflightChecker
from scanner import TargetScanner, ScanContext
from ui import C, print_banner, print_config, print_live_finding, print_target_summary, print_global_summary, generate_report

# 为类型提示定义Services
Services = ForwardRef('Services')

@dataclass
class Services:
    """依赖注入的服务容器"""
    waf_detector: WAFDetector
    secret_finder: SecretFinder
    preflight_checker: PreflightChecker

class ScanController:
    """管理整个扫描会话"""
    def __init__(self, args, services: Services):
        self.args = args
        self.services = services
        self.config = ScannerConfig(args.payload_host)
        self.all_results = []
        self.start_time = time.time()
        self.targets_with_waf = {}
        self.custom_paths = self.config.load_custom_paths()
        self.session = None
        self.total_targets = 0
        self.completed_targets = 0
        self.global_pbar = None
        self.target_stats = defaultdict(dict)
        self.targets = []
        self.worker_tasks = []

    def _load_targets(self) -> List[str]:
        initial_targets = []
        if self.args.url:
            initial_targets.append(self.args.url)
        else:
            try:
                with open(self.args.list, 'r') as f:
                    initial_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if not initial_targets:
                    logging.error(f"文件 '{self.args.list}' 为空或无效。"); sys.exit(1)
            except FileNotFoundError:
                logging.error(f"文件未找到: {self.args.list}"); sys.exit(1)
        
        if not self.args.fuzz_paths: return initial_targets
        
        logging.info(f"{C.BOLD}[模式] 路径模糊测试已启用...{C.ENDC}")
        final_targets_set = set(initial_targets)
        base_domains = {urllib.parse.urlunparse((p.scheme, p.netloc, '', '', '', '')) for p in [urllib.parse.urlparse(t) for t in initial_targets]}
        
        all_paths = self._generate_smart_paths()
        max_paths = min(self.args.max_fuzz_paths, len(all_paths))
        all_paths = all_paths[:max_paths]
        
        for domain in base_domains:
            for path in all_paths:
                new_target = urllib.parse.urljoin(domain, path)
                if new_target not in final_targets_set:
                    final_targets_set.add(new_target)
        
        return list(final_targets_set)

    def _generate_smart_paths(self) -> List[str]:
        smart_paths = set(ScannerConfig.REDIRECT_COMMON_PATHS + self.custom_paths)
        return sorted(list(smart_paths))

    async def _process_target(self, target: str, context: ScanContext):
        start_t = time.time()
        try:
            if not await context.services.preflight_checker.is_scannable(context.session, target, C):
                self.target_stats[target] = {'status': 'skipped', 'duration': time.time() - start_t}
                return

            extra_params = set()
            if self.args.find_secrets:
                extra_params = await context.services.secret_finder.find(context.session, target, C)

            scanner = TargetScanner(target, context, extra_params)
            results = await scanner.run()
            
            if results:
                for r in results:
                    self.all_results.append(r)
                    print_live_finding(r)
            
            self.target_stats[target] = {
                'vulns': len(results),
                'duration': time.time() - start_t,
                'requests': scanner.total_requests if hasattr(scanner, 'total_requests') else 0,
                'errors': sum(scanner.errors.values())
            }
        except Exception as e:
            logging.error(f"处理目标 {target} 时发生意外错误: {e}", exc_info=True)
            self.target_stats[target] = {'error': str(e), 'duration': time.time() - start_t}
        finally:
            self.completed_targets += 1
            if self.global_pbar: self.global_pbar.update(1)
            print_target_summary(target, self.target_stats[target], self.targets_with_waf.get(target))

    async def _worker(self, queue: asyncio.Queue, context: ScanContext):
        """从队列中获取目标并处理的工作协程"""
        while not queue.empty():
            try:
                target = await queue.get()
                await self._process_target(target, context)
                queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Worker 协程遇到错误: {e}", exc_info=True)
                break

    async def start(self):
        self.targets = self._load_targets()
        self.total_targets = len(self.targets)
        
        print_banner()
        print_config(self.args, self.total_targets)

        try:
            from tqdm import tqdm
            self.global_pbar = tqdm(total=self.total_targets, desc=f'{C.BOLD}全局进度{C.ENDC}', 
                                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
                                    file=sys.stdout, colour='cyan')
        except (ImportError, ModuleNotFoundError):
            self.global_pbar = None
        
        connector = aiohttp.TCPConnector(limit_per_host=self.args.concurrency_per_domain, enable_cleanup_closed=True, ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            self.session = session
            context = ScanContext(self.args, session, self.config, self.services)
            
            if not self.args.skip_waf_detect:
                logging.info(f"{C.CYAN}--- 开始进行WAF/CDN探测 ---{C.ENDC}")
                waf_tasks = [context.services.waf_detector.detect(session, target) for target in self.targets]
                waf_results = await asyncio.gather(*waf_tasks)
                for target, waf in zip(self.targets, waf_results):
                    if waf: self.targets_with_waf[target] = waf
                logging.info(f"{C.CYAN}--- WAF/CDN探测完成 ---{C.ENDC}")

            logging.info(f"{C.CYAN}--- 开始主扫描任务 ---{C.ENDC}")
            
            queue = asyncio.Queue()
            for target in self.targets:
                await queue.put(target)

            self.worker_tasks = [
                asyncio.create_task(self._worker(queue, context))
                for _ in range(self.args.concurrency)
            ]

            await queue.join()

            for task in self.worker_tasks:
                task.cancel()
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)

        await self._shutdown()

    async def _shutdown(self):
        if self.global_pbar: self.global_pbar.close()
        
        if self.all_results:
            generate_report(self.args, self.all_results, self.targets, self.start_time, self.targets_with_waf)
        print_global_summary(self.start_time, self.all_results, self.target_stats, self.targets_with_waf)
        
        if self.session and not self.session.closed:
            await self.session.close()
        
        if platform.system() != "Windows":
            try:
                mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
                logging.info(f"[{C.BLUE}资源使用{C.ENDC}] 峰值内存: {mem_usage:.2f} MB")
            except Exception:
                pass

    async def handle_interrupt(self):
        logging.info(f"\n{C.ORANGE}[中断] 正在优雅地停止任务...{C.ENDC}")
        for task in self.worker_tasks:
            task.cancel()
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        await self._shutdown()
