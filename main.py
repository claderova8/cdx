#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级异步开放重定向漏洞扫描工具 (V16 模块化版)
主入口文件
"""
import asyncio
import argparse
import sys
import logging

from controller import ScanController, Services
from services import WAFDetector, SecretFinder, PreflightChecker
from ui import setup_logging, C

def main():
    parser = argparse.ArgumentParser(
        description='高级异步开放重定向漏洞扫描工具 (V16 模块化版)',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"作者: {C.CYAN}Gemini{C.ENDC}"
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-u', '--url', help='单个目标URL')
    input_group.add_argument('-l', '--list', help='包含多个目标URL的文件路径')
    
    parser.add_argument('--fuzz-paths', action='store_true', help='对每个基础域名模糊测试常见的跳转路径')
    parser.add_argument('--find-secrets', action='store_true', help='通过分析JS/HTML/SourceMap发现隐藏的重定向参数')
    parser.add_argument('--payload-host', default='www.bing.com', help='用于测试重定向的外部主机名')
    parser.add_argument('-c', '--concurrency', type=int, default=50, help='全局并发请求数')
    parser.add_argument('--concurrency-per-domain', type=int, default=10, help='每个域名的最大并发请求数')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间（秒）')
    parser.add_argument('-s', '--stop-on-first', action='store_true', help='在目标上发现第一个漏洞后立即停止扫描')
    parser.add_argument('-o', '--output', help='报告文件名')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细模式（开启DEBUG日志）')
    parser.add_argument('--smart-post', choices=['all', 'json', 'form'], default='json', 
                        help='智能POST测试模式: all=测试所有格式, json=优先测试JSON, form=优先测试表单')
    
    # 新增参数
    parser.add_argument('--max-params-per-target', type=int, default=100, 
                        help='每个目标测试的最大参数数量')
    parser.add_argument('--max-fuzz-paths', type=int, default=100, 
                        help='路径模糊测试的最大路径数量')
    parser.add_argument('--skip-waf-detect', action='store_true', 
                        help='跳过WAF检测阶段')
    
    args = parser.parse_args()
    
    if args.smart_post == 'all':
        args.smart_post = ['json', 'form']
    else:
        args.smart_post = [args.smart_post]
    
    root_logger = setup_logging()
    if args.verbose: 
        root_logger.setLevel(logging.DEBUG)
        logging.debug("详细模式已启用")

    services = Services(
        waf_detector=WAFDetector(),
        secret_finder=SecretFinder(),
        preflight_checker=PreflightChecker()
    )
    controller = ScanController(args, services)
    
    loop = asyncio.get_event_loop()
    main_task = None
    try:
        main_task = loop.create_task(controller.start())
        loop.run_until_complete(main_task)
    except KeyboardInterrupt:
        logging.info("捕获到中断信号...")
        if main_task:
            main_task.cancel()
        # 适配性改动: 调用异步的中断处理函数
        loop.run_until_complete(controller.handle_interrupt())
    except Exception as e:
        logging.error(f"发生未处理的严重错误: {e}", exc_info=True)
    finally:
        # 确保事件循环在所有情况下都能正确关闭
        tasks = [t for t in asyncio.all_tasks(loop=loop) if t is not asyncio.current_task(loop=loop)]
        if tasks:
            loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.close()

if __name__ == '__main__':
    main()
