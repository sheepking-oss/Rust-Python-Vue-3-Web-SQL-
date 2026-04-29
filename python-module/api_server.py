from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import subprocess
import threading
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from sql_injection_detector import SQLInjectionDetector, finding_to_dict
from replay_tester import ReplayTester, replay_result_to_dict

app = Flask(__name__)
CORS(app)

scan_results: Dict[str, Any] = {}
malicious_ips: Dict[str, Dict[str, Any]] = {}
vulnerability_stats: Dict[str, Any] = {
    'total_scans': 0,
    'total_findings': 0,
    'confirmed_vulnerabilities': 0,
    'by_type': {
        'UNION-Based': 0,
        'Error-Based': 0,
        'Boolean-Based': 0,
        'Time-Based': 0,
        'Blind': 0,
        'Comment': 0,
        'Stacked Queries': 0
    }
}

DATA_DIR = Path(__file__).parent / 'data'
DATA_DIR.mkdir(exist_ok=True)

def load_saved_data():
    global scan_results, malicious_ips, vulnerability_stats
    
    results_file = DATA_DIR / 'scan_results.json'
    if results_file.exists():
        with open(results_file, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
    
    ips_file = DATA_DIR / 'malicious_ips.json'
    if ips_file.exists():
        with open(ips_file, 'r', encoding='utf-8') as f:
            malicious_ips = json.load(f)
    
    stats_file = DATA_DIR / 'vulnerability_stats.json'
    if stats_file.exists():
        with open(stats_file, 'r', encoding='utf-8') as f:
            vulnerability_stats = json.load(f)

def save_data():
    with open(DATA_DIR / 'scan_results.json', 'w', encoding='utf-8') as f:
        json.dump(scan_results, f, ensure_ascii=False, indent=2)
    
    with open(DATA_DIR / 'malicious_ips.json', 'w', encoding='utf-8') as f:
        json.dump(malicious_ips, f, ensure_ascii=False, indent=2)
    
    with open(DATA_DIR / 'vulnerability_stats.json', 'w', encoding='utf-8') as f:
        json.dump(vulnerability_stats, f, ensure_ascii=False, indent=2)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    return jsonify({
        'vulnerability_stats': vulnerability_stats,
        'malicious_ips_count': len(malicious_ips),
        'active_scans': len([r for r in scan_results.values() if r.get('status') == 'running']),
        'recent_findings': get_recent_findings(10)
    })

@app.route('/api/malicious-ips', methods=['GET'])
def get_malicious_ips():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    ips_list = list(malicious_ips.values())
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'total': len(ips_list),
        'page': page,
        'per_page': per_page,
        'data': ips_list[start:end]
    })

@app.route('/api/malicious-ips/<ip>', methods=['GET'])
def get_malicious_ip_details(ip):
    if ip in malicious_ips:
        return jsonify(malicious_ips[ip])
    return jsonify({'error': 'IP not found'}), 404

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    status_filter = request.args.get('status')
    type_filter = request.args.get('type')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    all_findings = []
    for result in scan_results.values():
        findings = result.get('findings', [])
        for finding in findings:
            all_findings.append(finding)
    
    if status_filter:
        all_findings = [f for f in all_findings if f.get('severity') == status_filter]
    
    if type_filter:
        all_findings = [
            f for f in all_findings 
            if any(p.get('injection_type') == type_filter for p in f.get('payloads', []))
        ]
    
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'total': len(all_findings),
        'page': page,
        'per_page': per_page,
        'data': all_findings[start:end]
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    pcap_file = data.get('pcap_file')
    sessions_json = data.get('sessions_json')
    base_url = data.get('base_url')
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    scan_results[scan_id] = {
        'scan_id': scan_id,
        'status': 'running',
        'start_time': datetime.now().isoformat(),
        'findings': [],
        'replay_results': []
    }
    
    def run_scan():
        try:
            if sessions_json:
                detector = SQLInjectionDetector()
                findings = detector.analyze_sessions_file(sessions_json)
                findings_dicts = [finding_to_dict(f) for f in findings]
                
                scan_results[scan_id]['findings'] = findings_dicts
                update_statistics(findings_dicts)
                update_malicious_ips(findings_dicts)
                
                if base_url and findings_dicts:
                    tester = ReplayTester()
                    replay_results = []
                    for finding in findings_dicts:
                        try:
                            result = tester.test_vulnerability(finding, base_url=base_url)
                            replay_results.append(replay_result_to_dict(result))
                            
                            if result.status.value == 'CONFIRMED':
                                vulnerability_stats['confirmed_vulnerabilities'] += 1
                        except Exception as e:
                            replay_results.append({
                                'finding_id': finding.get('session_id', ''),
                                'status': 'ERROR',
                                'error_message': str(e),
                                'confidence': 0.0
                            })
                    
                    tester.close()
                    scan_results[scan_id]['replay_results'] = replay_results
            
            scan_results[scan_id]['status'] = 'completed'
            scan_results[scan_id]['end_time'] = datetime.now().isoformat()
            save_data()
            
        except Exception as e:
            scan_results[scan_id]['status'] = 'failed'
            scan_results[scan_id]['error'] = str(e)
            scan_results[scan_id]['end_time'] = datetime.now().isoformat()
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'running',
        'message': 'Scan started'
    })

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    scans_list = list(scan_results.values())
    scans_list.sort(key=lambda x: x.get('start_time', ''), reverse=True)
    
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'total': len(scans_list),
        'page': page,
        'per_page': per_page,
        'data': scans_list[start:end]
    })

@app.route('/api/replay', methods=['POST'])
def run_replay_test():
    data = request.get_json()
    
    if not data or 'finding' not in data:
        return jsonify({'error': 'Finding data required'}), 400
    
    finding = data['finding']
    base_url = data.get('base_url')
    timeout = data.get('timeout', 10)
    
    tester = ReplayTester(timeout=timeout)
    
    try:
        result = tester.test_vulnerability(finding, base_url=base_url)
        result_dict = replay_result_to_dict(result)
        tester.close()
        
        return jsonify(result_dict)
        
    except Exception as e:
        tester.close()
        return jsonify({
            'status': 'ERROR',
            'error_message': str(e)
        }), 500

def update_statistics(findings: List[Dict[str, Any]]):
    vulnerability_stats['total_scans'] += 1
    vulnerability_stats['total_findings'] += len(findings)
    
    for finding in findings:
        for payload in finding.get('payloads', []):
            inj_type = payload.get('injection_type')
            if inj_type in vulnerability_stats['by_type']:
                vulnerability_stats['by_type'][inj_type] += 1

def update_malicious_ips(findings: List[Dict[str, Any]]):
    for finding in findings:
        source_ip = finding.get('source_ip')
        dest_ip = finding.get('dest_ip')
        
        if source_ip and source_ip not in malicious_ips:
            malicious_ips[source_ip] = {
                'ip': source_ip,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'attack_count': 1,
                'attack_types': [],
                'targets': [dest_ip] if dest_ip else [],
                'severity': finding.get('severity', 'MEDIUM')
            }
        elif source_ip in malicious_ips:
            malicious_ips[source_ip]['last_seen'] = datetime.now().isoformat()
            malicious_ips[source_ip]['attack_count'] += 1
            
            for payload in finding.get('payloads', []):
                inj_type = payload.get('injection_type')
                if inj_type not in malicious_ips[source_ip]['attack_types']:
                    malicious_ips[source_ip]['attack_types'].append(inj_type)
            
            if dest_ip and dest_ip not in malicious_ips[source_ip]['targets']:
                malicious_ips[source_ip]['targets'].append(dest_ip)

def get_recent_findings(limit: int = 10) -> List[Dict[str, Any]]:
    all_findings = []
    for result in scan_results.values():
        for finding in result.get('findings', []):
            all_findings.append({
                **finding,
                'scan_time': result.get('start_time')
            })
    
    all_findings.sort(key=lambda x: x.get('scan_time', ''), reverse=True)
    return all_findings[:limit]

if __name__ == '__main__':
    load_saved_data()
    print("API Server starting on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
