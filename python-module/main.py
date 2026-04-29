import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any

from sql_injection_detector import SQLInjectionDetector, finding_to_dict
from replay_tester import ReplayTester, replay_result_to_dict, VulnerabilityStatus

def parse_args():
    parser = argparse.ArgumentParser(
        description='流量分析与 SQL 注入漏洞检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    detect_parser = subparsers.add_parser('detect', help='检测 SQL 注入漏洞')
    detect_parser.add_argument('-i', '--input', required=True, help='Rust 引擎输出的 JSON 文件路径')
    detect_parser.add_argument('-o', '--output', help='输出结果 JSON 文件路径')
    detect_parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')

    replay_parser = subparsers.add_parser('replay', help='漏洞重放测试')
    replay_parser.add_argument('-i', '--input', required=True, help='检测结果 JSON 文件路径')
    replay_parser.add_argument('-o', '--output', help='输出结果 JSON 文件路径')
    replay_parser.add_argument('-u', '--url', help='基础 URL（用于构建完整的目标 URL）')
    replay_parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间（秒）')
    replay_parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')

    scan_parser = subparsers.add_parser('scan', help='完整扫描（检测 + 重放）')
    scan_parser.add_argument('-i', '--input', required=True, help='Rust 引擎输出的 JSON 文件路径')
    scan_parser.add_argument('-o', '--output', help='输出结果 JSON 文件路径')
    scan_parser.add_argument('-u', '--url', help='基础 URL')
    scan_parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间（秒）')
    scan_parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')

    return parser.parse_args()

def run_detection(input_file: str, verbose: bool = False) -> List[Dict[str, Any]]:
    if verbose:
        print(f"[*] 开始检测 SQL 注入漏洞...")
        print(f"[*] 输入文件: {input_file}")

    detector = SQLInjectionDetector()
    findings = detector.analyze_sessions_file(input_file)

    if verbose:
        print(f"[+] 检测完成，发现 {len(findings)} 个潜在漏洞")
        for i, finding in enumerate(findings, 1):
            print(f"\n  [{i}] 会话 ID: {finding.session_id}")
            print(f"      源 IP: {finding.source_ip}")
            print(f"      目标 IP: {finding.dest_ip}")
            print(f"      URL: {finding.url}")
            print(f"      方法: {finding.method}")
            print(f"      Payloads 数量: {len(finding.payloads)}")
            
            for j, payload in enumerate(finding.payloads, 1):
                print(f"        [{j}] 类型: {payload.injection_type.value}")
                print(f"            置信度: {payload.confidence}")
                print(f"            位置: {payload.location}")
                print(f"            Payload: {payload.payload[:80]}")

    return [finding_to_dict(f) for f in findings]

def run_replay(
    findings: List[Dict[str, Any]],
    base_url: str = None,
    timeout: int = 10,
    verbose: bool = False
) -> List[Dict[str, Any]]:
    if verbose:
        print(f"[*] 开始漏洞重放测试...")
        print(f"[*] 超时时间: {timeout} 秒")
        if base_url:
            print(f"[*] 基础 URL: {base_url}")

    tester = ReplayTester(timeout=timeout)
    results = []

    for i, finding in enumerate(findings, 1):
        if verbose:
            print(f"\n[*] 测试 [{i}/{len(findings)}]: {finding.get('url', 'N/A')}")
        
        try:
            result = tester.test_vulnerability(finding, base_url=base_url)
            result_dict = replay_result_to_dict(result)
            results.append(result_dict)

            if verbose:
                print(f"    状态: {result.status.value}")
                print(f"    置信度: {result.confidence}")
                for evidence in result.evidence:
                    print(f"      - {evidence}")
                
                if result.error_message:
                    print(f"    错误: {result.error_message}")

        except Exception as e:
            if verbose:
                print(f"    测试出错: {str(e)}")
            results.append({
                'finding_id': finding.get('session_id', ''),
                'target_url': finding.get('url', ''),
                'method': finding.get('method', ''),
                'status': 'ERROR',
                'error_message': str(e),
                'evidence': [],
                'confidence': 0.0
            })

    tester.close()

    if verbose:
        confirmed = sum(1 for r in results if r['status'] == 'CONFIRMED')
        unconfirmed = sum(1 for r in results if r['status'] == 'UNCONFIRMED')
        errors = sum(1 for r in results if r['status'] == 'ERROR')
        
        print(f"\n[+] 重放测试完成:")
        print(f"    确认漏洞: {confirmed}")
        print(f"    未确认: {unconfirmed}")
        print(f"    测试错误: {errors}")

    return results

def run_full_scan(
    input_file: str,
    base_url: str = None,
    timeout: int = 10,
    verbose: bool = False
) -> Dict[str, Any]:
    findings = run_detection(input_file, verbose)
    
    if not findings:
        return {
            'findings': [],
            'replay_results': [],
            'summary': {
                'total_findings': 0,
                'confirmed': 0,
                'unconfirmed': 0,
                'errors': 0
            }
        }

    replay_results = run_replay(findings, base_url, timeout, verbose)

    confirmed = sum(1 for r in replay_results if r['status'] == 'CONFIRMED')
    unconfirmed = sum(1 for r in replay_results if r['status'] == 'UNCONFIRMED')
    errors = sum(1 for r in replay_results if r['status'] == 'ERROR')

    return {
        'findings': findings,
        'replay_results': replay_results,
        'summary': {
            'total_findings': len(findings),
            'confirmed': confirmed,
            'unconfirmed': unconfirmed,
            'errors': errors
        }
    }

def save_output(data: Any, output_path: str):
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] 结果已保存到: {output_path}")

def main():
    args = parse_args()

    if args.command == 'detect':
        findings = run_detection(args.input, args.verbose)
        
        if args.output:
            save_output(findings, args.output)
        else:
            print(json.dumps(findings, indent=2, ensure_ascii=False))

    elif args.command == 'replay':
        with open(args.input, 'r', encoding='utf-8') as f:
            findings = json.load(f)
        
        results = run_replay(findings, args.url, args.timeout, args.verbose)
        
        if args.output:
            save_output(results, args.output)
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))

    elif args.command == 'scan':
        result = run_full_scan(args.input, args.url, args.timeout, args.verbose)
        
        if args.output:
            save_output(result, args.output)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))

    else:
        print("请使用 --help 查看可用命令")
        sys.exit(1)

if __name__ == '__main__':
    main()
