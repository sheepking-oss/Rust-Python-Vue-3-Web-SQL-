import requests
import re
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from enum import Enum

class VulnerabilityStatus(Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ERROR = "ERROR"

@dataclass
class ReplayTestResult:
    finding_id: str
    target_url: str
    method: str
    status: VulnerabilityStatus
    original_request: Dict[str, Any]
    test_request: Dict[str, Any]
    original_response: Dict[str, Any]
    test_response: Dict[str, Any]
    evidence: List[str]
    confidence: float
    error_message: Optional[str] = None

class ReplayTester:
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def test_vulnerability(
        self,
        finding: Dict[str, Any],
        base_url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> ReplayTestResult:
        method = finding.get('method', 'GET').upper()
        url = self._construct_url(finding, base_url)
        
        original_request = {
            'method': method,
            'url': url,
            'headers': headers or {},
            'body': finding.get('request_raw', '')
        }

        evidence = []
        confidence = 0.0

        try:
            payloads = finding.get('payloads', [])
            
            if any(p['injection_type'] == 'Time-Based' for p in payloads):
                result = self._test_time_based(url, method, payloads, headers)
                evidence.extend(result['evidence'])
                confidence = result['confidence']
                status = result['status']
            elif any(p['injection_type'] == 'Boolean-Based' for p in payloads):
                result = self._test_boolean_based(url, method, payloads, headers)
                evidence.extend(result['evidence'])
                confidence = result['confidence']
                status = result['status']
            elif any(p['injection_type'] == 'Error-Based' for p in payloads):
                result = self._test_error_based(url, method, payloads, headers)
                evidence.extend(result['evidence'])
                confidence = result['confidence']
                status = result['status']
            else:
                result = self._test_generic(url, method, payloads, headers)
                evidence.extend(result['evidence'])
                confidence = result['confidence']
                status = result['status']

            test_request = {
                'method': method,
                'url': url,
                'headers': headers or {},
                'payloads': payloads
            }

            original_response = {
                'status_code': result.get('original_status', 0),
                'body_preview': result.get('original_body', '')[:500] if result.get('original_body') else ''
            }

            test_response = {
                'status_code': result.get('test_status', 0),
                'body_preview': result.get('test_body', '')[:500] if result.get('test_body') else '',
                'response_time': result.get('response_time', 0)
            }

            return ReplayTestResult(
                finding_id=finding.get('session_id', ''),
                target_url=url,
                method=method,
                status=status,
                original_request=original_request,
                test_request=test_request,
                original_response=original_response,
                test_response=test_response,
                evidence=evidence,
                confidence=confidence
            )

        except requests.RequestException as e:
            return ReplayTestResult(
                finding_id=finding.get('session_id', ''),
                target_url=url,
                method=method,
                status=VulnerabilityStatus.ERROR,
                original_request=original_request,
                test_request={'error': str(e)},
                original_response={},
                test_response={},
                evidence=[],
                confidence=0.0,
                error_message=str(e)
            )

    def _construct_url(self, finding: Dict[str, Any], base_url: Optional[str]) -> str:
        uri = finding.get('url', '')
        
        if base_url and not uri.startswith(('http://', 'https://')):
            parsed_base = urlparse(base_url)
            if uri.startswith('/'):
                return urlunparse((parsed_base.scheme, parsed_base.netloc, uri, '', '', ''))
            else:
                return f"{base_url.rstrip('/')}/{uri.lstrip('/')}"
        
        if uri.startswith(('http://', 'https://')):
            return uri
        
        dest_ip = finding.get('dest_ip', '')
        if dest_ip:
            return f"http://{dest_ip}{uri}"
        
        return uri

    def _test_time_based(
        self,
        url: str,
        method: str,
        payloads: List[Dict[str, Any]],
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        evidence = []
        confidence = 0.0
        status = VulnerabilityStatus.UNCONFIRMED

        try:
            start_time = time.time()
            original_resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout
            )
            original_time = time.time() - start_time

            sleep_payloads = [p for p in payloads if 'sleep' in p['payload'].lower() or 'SLEEP' in p['payload']]
            
            for payload in sleep_payloads:
                test_url = self._inject_payload(url, payload['payload'], payload['location'])
                
                sleep_match = re.search(r'(?:sleep|SLEEP)\s*\(\s*(\d+)', payload['payload'])
                expected_sleep = int(sleep_match.group(1)) if sleep_match else 5

                start_time = time.time()
                try:
                    test_resp = self.session.request(
                        method, test_url, headers=headers, timeout=self.timeout + expected_sleep + 5
                    )
                    test_time = time.time() - start_time

                    evidence.append(f"原始响应时间: {original_time:.2f}s")
                    evidence.append(f"测试响应时间: {test_time:.2f}s")

                    if test_time >= original_time + expected_sleep - 1:
                        evidence.append(f"确认时间延迟: 响应增加了 {test_time - original_time:.2f}s")
                        confidence = min(1.0, 0.7 + (test_time - original_time) / 10)
                        status = VulnerabilityStatus.CONFIRMED
                        break

                except requests.Timeout:
                    evidence.append("请求超时，可能存在时间延迟")
                    confidence = 0.8
                    status = VulnerabilityStatus.CONFIRMED
                    break

            return {
                'evidence': evidence,
                'confidence': confidence,
                'status': status,
                'original_status': original_resp.status_code,
                'original_body': original_resp.text,
                'test_status': test_resp.status_code if 'test_resp' in locals() else 0,
                'test_body': test_resp.text if 'test_resp' in locals() else '',
                'response_time': test_time if 'test_time' in locals() else 0
            }

        except Exception as e:
            evidence.append(f"测试出错: {str(e)}")
            return {
                'evidence': evidence,
                'confidence': 0.0,
                'status': VulnerabilityStatus.ERROR,
                'original_status': 0,
                'original_body': '',
                'test_status': 0,
                'test_body': '',
                'response_time': 0
            }

    def _test_boolean_based(
        self,
        url: str,
        method: str,
        payloads: List[Dict[str, Any]],
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        evidence = []
        confidence = 0.0
        status = VulnerabilityStatus.UNCONFIRMED

        try:
            original_resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout
            )
            original_body = original_resp.text
            original_status = original_resp.status_code

            true_payloads = [p for p in payloads if '1=1' in p['payload'] or 'TRUE' in p['payload'].upper()]
            false_payloads = [p for p in payloads if '1=2' in p['payload'] or 'FALSE' in p['payload'].upper()]

            true_responses = []
            false_responses = []

            for payload in true_payloads:
                test_url = self._inject_payload(url, payload['payload'], payload['location'])
                resp = self.session.request(method, test_url, headers=headers, timeout=self.timeout)
                true_responses.append(resp)

            for payload in false_payloads:
                test_url = self._inject_payload(url, payload['payload'], payload['location'])
                resp = self.session.request(method, test_url, headers=headers, timeout=self.timeout)
                false_responses.append(resp)

            evidence.append(f"原始状态码: {original_status}")
            evidence.append(f"原始响应长度: {len(original_body)}")

            if true_responses and false_responses:
                true_body_len = len(true_responses[0].text)
                false_body_len = len(false_responses[0].text)
                
                evidence.append(f"True 条件响应长度: {true_body_len}")
                evidence.append(f"False 条件响应长度: {false_body_len}")

                if true_body_len != false_body_len:
                    evidence.append("检测到布尔条件响应差异，可能存在 SQL 注入")
                    
                    if len(original_body) == true_body_len:
                        evidence.append("原始响应与 True 条件一致")
                        confidence = 0.85
                    else:
                        confidence = 0.75
                    
                    status = VulnerabilityStatus.CONFIRMED

            return {
                'evidence': evidence,
                'confidence': confidence,
                'status': status,
                'original_status': original_status,
                'original_body': original_body,
                'test_status': true_responses[0].status_code if true_responses else 0,
                'test_body': true_responses[0].text if true_responses else '',
                'response_time': 0
            }

        except Exception as e:
            evidence.append(f"测试出错: {str(e)}")
            return {
                'evidence': evidence,
                'confidence': 0.0,
                'status': VulnerabilityStatus.ERROR,
                'original_status': 0,
                'original_body': '',
                'test_status': 0,
                'test_body': '',
                'response_time': 0
            }

    def _test_error_based(
        self,
        url: str,
        method: str,
        payloads: List[Dict[str, Any]],
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        evidence = []
        confidence = 0.0
        status = VulnerabilityStatus.UNCONFIRMED

        error_indicators = [
            r'(?i)sql.*syntax',
            r'(?i)mysql.*error',
            r'(?i)ora-\d+',
            r'(?i)postgresql.*error',
            r'(?i)microsoft.*sql',
            r'(?i)unclosed.*quotation',
            r'(?i)invalid.*column',
            r'(?i)conversion.*failed',
            r'(?i)divide by zero',
            r'(?i)xpath.*error',
            r'(?i)extractvalue',
            r'(?i)updatexml',
        ]

        try:
            original_resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout
            )
            original_body = original_resp.text

            has_original_error = any(re.search(pattern, original_body) for pattern in error_indicators)
            
            if has_original_error:
                evidence.append("原始请求已包含 SQL 错误信息")
                confidence = 0.9
                status = VulnerabilityStatus.CONFIRMED

            for payload in payloads:
                test_url = self._inject_payload(url, payload['payload'], payload['location'])
                resp = self.session.request(method, test_url, headers=headers, timeout=self.timeout)
                test_body = resp.text

                for pattern in error_indicators:
                    matches = re.findall(pattern, test_body)
                    for match in matches:
                        evidence.append(f"检测到 SQL 错误: {match[:100]}")
                        confidence = max(confidence, 0.95)
                        status = VulnerabilityStatus.CONFIRMED

                if resp.status_code == 500 and original_resp.status_code != 500:
                    evidence.append(f"服务器错误 (500)，可能由 SQL 注入引起")
                    confidence = max(confidence, 0.6)

            return {
                'evidence': evidence,
                'confidence': confidence,
                'status': status,
                'original_status': original_resp.status_code,
                'original_body': original_body,
                'test_status': resp.status_code if 'resp' in locals() else 0,
                'test_body': test_body if 'test_body' in locals() else '',
                'response_time': 0
            }

        except Exception as e:
            evidence.append(f"测试出错: {str(e)}")
            return {
                'evidence': evidence,
                'confidence': 0.0,
                'status': VulnerabilityStatus.ERROR,
                'original_status': 0,
                'original_body': '',
                'test_status': 0,
                'test_body': '',
                'response_time': 0
            }

    def _test_generic(
        self,
        url: str,
        method: str,
        payloads: List[Dict[str, Any]],
        headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        evidence = []
        confidence = 0.0
        status = VulnerabilityStatus.UNCONFIRMED

        try:
            original_resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout
            )

            evidence.append(f"目标 URL: {url}")
            evidence.append(f"方法: {method}")
            evidence.append(f"检测到 {len(payloads)} 个潜在恶意 payload")
            
            for payload in payloads:
                evidence.append(f"  - 类型: {payload['injection_type']}, 置信度: {payload['confidence']}")
                evidence.append(f"    Payload: {payload['payload'][:100]}")

            confidence = max((p['confidence'] for p in payloads), default=0.5)

            return {
                'evidence': evidence,
                'confidence': confidence,
                'status': status,
                'original_status': original_resp.status_code,
                'original_body': original_resp.text,
                'test_status': 0,
                'test_body': '',
                'response_time': 0
            }

        except Exception as e:
            evidence.append(f"测试出错: {str(e)}")
            return {
                'evidence': evidence,
                'confidence': 0.0,
                'status': VulnerabilityStatus.ERROR,
                'original_status': 0,
                'original_body': '',
                'test_status': 0,
                'test_body': '',
                'response_time': 0
            }

    def _inject_payload(self, url: str, payload: str, location: str) -> str:
        parsed = urlparse(url)
        
        if location == "URI" or '=' in parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            
            for key in query_params:
                if len(query_params[key]) > 0:
                    original_value = query_params[key][0]
                    if "'" in original_value or '"' in original_value or '=' in original_value:
                        query_params[key] = [original_value]
                    else:
                        query_params[key] = [f"{original_value}{payload}"]
            
            new_query = urlencode(query_params, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        
        return url

    def close(self):
        self.session.close()

def replay_result_to_dict(result: ReplayTestResult) -> Dict[str, Any]:
    return {
        'finding_id': result.finding_id,
        'target_url': result.target_url,
        'method': result.method,
        'status': result.status.value,
        'original_request': result.original_request,
        'test_request': result.test_request,
        'original_response': result.original_response,
        'test_response': result.test_response,
        'evidence': result.evidence,
        'confidence': result.confidence,
        'error_message': result.error_message
    }
