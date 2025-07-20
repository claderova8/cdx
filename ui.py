# -*- coding: utf-8 -*-
"""
模块：用户界面与报告 (打印信息优化版)
- Colors: 管理终端颜色
- TqdmLoggingHandler: 避免日志与tqdm进度条冲突
- 所有与打印（banner, config, results, summary）和生成报告相关的函数
"""
import sys
import logging
import json
import time
import argparse
from collections import defaultdict
from typing import List, Dict

# --- 颜色与日志配置 ---
class Colors:
    GREEN, YELLOW, RED, ORANGE, BOLD, BLUE, PURPLE, CYAN, ENDC = '\033[92m', '\033[93m', '\033[91m', '\033[33m', '\033[1m', '\033[94m', '\033[95m', '\033[96m', '\033[0m'

class NoColors:
    GREEN = YELLOW = RED = ORANGE = BOLD = BLUE = PURPLE = CYAN = ENDC = ''

C = Colors if sys.stdout.isatty() else NoColors

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='%H:%M:%S')

    class TqdmLoggingHandler(logging.Handler):
        def emit(self, record):
            try:
                from tqdm import tqdm
                tqdm.write(self.format(record), file=sys.stderr)
                self.flush()
            except (ImportError, ModuleNotFoundError):
                sys.stderr.write(self.format(record) + '\n')
            except Exception:
                self.handleError(record)

    root_logger = logging.getLogger()
    if not any(isinstance(h, TqdmLoggingHandler) for h in root_logger.handlers):
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        root_logger.addHandler(TqdmLoggingHandler())
    return root_logger

def print_banner():
    banner = f"""
{C.CYAN}
    ____              __  __          _     _____               _          
   / __ \            / / / /         | |   / ____|             | |         
  | |  | |_ __      / / / /_   ______| |  | (___   _ __  _ __ | | ___ _ __ 
  | |  | | '_ \    / / / /\\ \\ /\\ / / _` |   \\___ \\| | | |/ __|| __/ _ \\| '__|
  | |__| | | | |  / / / /  \\ V  V / (_| |   ____) | |_| | (__ | ||  __/|   
   \\____/|_| |_| /_/ /_/    \\_/\\_/ \\__,_|  |_____/ \\__, |___/ \\__\\___|_|   
                                                    __/ |                  
                                                   |___/                   
{C.BOLD}Advanced Async Open Redirect Scanner - V17 (UI Enhanced){C.ENDC}
"""
    print(banner)

def print_config(args: argparse.Namespace, total_targets: int):
    target_src = args.url if args.url else args.list
    
    def mode_status(status, text):
        return f"{C.GREEN}✔ {text}{C.ENDC}" if status else f"{C.RED}✖ {text}{C.ENDC}"

    # 修复: 避免使用嵌套的f-string
    smart_post_text = '智能POST测试: ' + ", ".join(args.smart_post)

    config_details = (
        f"{C.CYAN}╭─{'─'*22}┤ {C.BOLD}扫描配置{C.ENDC}{C.CYAN} ├{'─'*22}─╮{C.ENDC}\n"
        f"{C.CYAN}│{C.ENDC} {C.BOLD}{'目标源:':<18}{C.ENDC} {target_src}\n"
        f"{C.CYAN}│{C.ENDC} {C.BOLD}{'总目标数:':<18}{C.ENDC} {total_targets}\n"
        f"{C.CYAN}│{C.ENDC} {C.BOLD}{'Payload Host:':<18}{C.ENDC} {args.payload_host}\n"
        f"{C.CYAN}│{C.ENDC} {C.BOLD}{'并发数 (全局/域):':<18}{C.ENDC} {args.concurrency} / {args.concurrency_per_domain}\n"
        f"{C.CYAN}│{C.ENDC} {C.BOLD}{'超时时间:':<18}{C.ENDC} {args.timeout} 秒\n"
        f"{C.CYAN}├─{'─'*15}┤ {C.BOLD}扫描模式{C.ENDC}{C.CYAN} ├{'─'*28}─┤{C.ENDC}\n"
        f"{C.CYAN}│{C.ENDC} {mode_status(args.find_secrets, '发现秘密参数')}\n"
        f"{C.CYAN}│{C.ENDC} {mode_status(args.fuzz_paths, '路径模糊测试')}\n"
        f"{C.CYAN}│{C.ENDC} {mode_status(True, smart_post_text)}\n"
        f"{C.CYAN}│{C.ENDC} {mode_status(args.stop_on_first, '发现后停止')}\n"
        f"{C.CYAN}│{C.ENDC} {mode_status(not args.skip_waf_detect, 'WAF/CDN探测')}\n"
        f"{C.CYAN}╰─{'─'*60}─╯{C.ENDC}"
    )
    print(config_details)

def print_live_finding(r):
    import urllib.parse
    color_map = {
        "CRITICAL": C.PURPLE, "HIGH": C.RED, "MEDIUM": C.ORANGE, "LOW": C.YELLOW
    }
    color = color_map.get(r.severity, C.ENDC)
    
    display_url = urllib.parse.unquote(r.url)
    if len(display_url) > 75:
        display_url = display_url[:72] + '...'

    details = (
        f"\n{color}╔══════════════════════════════════════════════════════════════╗{C.ENDC}\n"
        f"{color}║ {C.BOLD}[漏洞发现] 开放重定向 - {r.severity:<8}{C.ENDC}{color} ║{C.ENDC}\n"
        f"{color}╠══════════════════════════════════════════════════════════════╣{C.ENDC}\n"
        f"{color}║ {C.ENDC}{C.CYAN}{'目标:':<10}{C.ENDC} {r.target}\n"
        f"{color}║ {C.ENDC}{C.CYAN}{'参数:':<10}{C.ENDC} {C.BLUE}{r.param_name}{C.ENDC}\n"
        f"{color}║ {C.ENDC}{C.CYAN}{'方法:':<10}{C.ENDC} {r.method}\n"
        f"{color}║ {C.ENDC}{C.CYAN}{'Payload:':<10}{C.ENDC} {r.payload}\n"
        f"{color}║ {C.ENDC}{C.CYAN}{'证据:':<10}{C.ENDC} {r.evidence}\n"
        f"{color}╟──────────────────────────────────────────────────────────────╢{C.ENDC}\n"
        f"{color}║ {C.ENDC}{C.CYAN}{'完整URL:':<10}{C.ENDC} {display_url}\n"
        f"{color}╚══════════════════════════════════════════════════════════════╝{C.ENDC}"
    )
    logging.info(details)

def print_target_summary(target: str, stats: dict, waf_info: str):
    waf_display = f" {C.ORANGE}(WAF: {waf_info}){C.ENDC}" if waf_info else ""
    
    if 'error' in stats:
        status = f"{C.RED}错误{C.ENDC}"
    else:
        vulns = stats.get('vulns', 0)
        status = f"{C.RED}发现 {vulns} 个漏洞{C.ENDC}" if vulns > 0 else f"{C.GREEN}安全{C.ENDC}"
    
    duration = stats.get('duration', 0)
    summary = (f"[{C.CYAN}»{C.ENDC}] {target:<60.60} {C.BOLD}»{C.ENDC} "
               f"耗时: {duration:<5.2f}s {C.BOLD}»{C.ENDC} "
               f"状态: {status}{waf_display}")
    from tqdm import tqdm
    tqdm.write(summary)

def _format_time(seconds: float) -> str:
    if seconds < 60: return f"{seconds:.1f} 秒"
    if seconds < 3600: return f"{seconds / 60:.1f} 分钟"
    return f"{seconds / 3600:.1f} 小时"

def print_global_summary(start_time, all_results, target_stats, targets_with_waf):
    total_time = time.time() - start_time
    vulnerable_targets = {r.target for r in all_results}
    
    severity_counts = defaultdict(int)
    for r in all_results:
        severity_counts[r.severity] += 1
        
    total_requests = sum(stats.get('requests', 0) for stats in target_stats.values())
    total_errors = sum(stats.get('errors', 0) for stats in target_stats.values())
    error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0
    req_per_sec = total_requests / total_time if total_time > 0 else 0

    summary = (
        f"\n{C.CYAN}╔═══════════════════════════════ 全局扫描摘要 ═══════════════════════════════╗{C.ENDC}\n"
        f"{C.CYAN}║{C.ENDC}\n"
        f"{C.CYAN}║ {C.BOLD}{'总耗时:':<18}{C.ENDC} {_format_time(total_time)}\n"
        f"{C.CYAN}║ {C.BOLD}{'总目标数:':<18}{C.ENDC} {len(target_stats)}\n"
        f"{C.CYAN}║ {C.BOLD}{'受影响目标数:':<18}{C.ENDC} {C.ORANGE}{len(vulnerable_targets)}{C.ENDC}\n"
        f"{C.CYAN}║ {C.BOLD}{'总请求数:':<18}{C.ENDC} {total_requests} ({req_per_sec:.1f} req/s, 错误率: {error_rate:.1f}%)\n"
        f"{C.CYAN}║{C.ENDC}\n"
        f"{C.CYAN}╟─────────────────────────────── 漏洞统计 ───────────────────────────────╢{C.ENDC}\n"
        f"{C.CYAN}║ {C.PURPLE}{'CRITICAL:':<12}{C.ENDC} {severity_counts['CRITICAL']:<5} {C.RED}{'HIGH:':<8}{C.ENDC} {severity_counts['HIGH']:<5} "
        f"{C.ORANGE}{'MEDIUM:':<9}{C.ENDC} {severity_counts['MEDIUM']:<5} {C.YELLOW}{'LOW:':<6}{C.ENDC} {severity_counts['LOW']:<5} "
        f"{C.BOLD}{'总计:':<7}{C.ENDC} {C.RED}{len(all_results)}{C.ENDC}\n"
        f"{C.CYAN}║{C.ENDC}\n"
        f"{C.CYAN}╚════════════════════════════════════════════════════════════════════════════╝{C.ENDC}"
    )
    
    if all_results:
        summary += f"\n{C.GREEN}报告已生成。{C.ENDC}"
    else:
        summary += f"\n{C.GREEN}扫描完成，未发现漏洞。{C.ENDC}"

    logging.info(summary)

def generate_report(args, all_results, targets, start_time, targets_with_waf):
    if not all_results:
        return

    import urllib.parse
    if args.output:
        fname = args.output
    elif targets:
        first_target_domain = urllib.parse.urlparse(targets[0]).netloc
        sanitized_domain = first_target_domain.replace(":", "_")
        fname = f"{sanitized_domain}_report.json"
    else:
        fname = f"redirect_report_{int(time.time())}.json"
    
    vuln_by_severity = defaultdict(list)
    for r in all_results:
        vuln_by_severity[r.severity].append(r.to_dict())
    
    report_data = {
        "scan_metadata": {
            "scan_start_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)),
            "total_duration_seconds": f"{time.time() - start_time:.2f}",
            "payload_host": args.payload_host,
            "targets_with_waf": targets_with_waf,
            "total_targets": len(targets),
            "vulnerable_targets": len({r.target for r in all_results})
        },
        "vulnerabilities_by_severity": vuln_by_severity,
    }
    try:
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        logging.info(f"{C.GREEN}报告已保存至: {fname}{C.ENDC}")
    except IOError as e:
        logging.error(f"无法写入报告文件 {fname}: {e}")
