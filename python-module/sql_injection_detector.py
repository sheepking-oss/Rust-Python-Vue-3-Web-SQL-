import re
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class SQLInjectionType(Enum):
    UNION_BASED = "UNION-Based"
    ERROR_BASED = "Error-Based"
    BOOLEAN_BASED = "Boolean-Based"
    TIME_BASED = "Time-Based"
    BLIND = "Blind"
    COMMENT = "Comment"
    STACKED_QUERIES = "Stacked Queries"

@dataclass
class SQLPayload:
    payload: str
    injection_type: SQLInjectionType
    location: str
    confidence: float
    context: str

@dataclass 
class VulnerabilityFinding:
    session_id: str
    source_ip: str
    dest_ip: str
    url: str
    method: str
    payloads: List[SQLPayload]
    request_raw: str
    response_raw: str
    timestamp: Optional[str] = None

class SQLInjectionDetector:
    def __init__(self):
        self.patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[SQLInjectionType, List[str]]:
        return {
            SQLInjectionType.UNION_BASED: [
                r'\bUNION\s+(?:ALL\s+)?SELECT\b',
                r'\bUNION\s+SELECT\b',
                r'\bSELECT\s+.*\s+FROM\b',
            ],
            SQLInjectionType.ERROR_BASED: [
                r'\bAND\s+EXTRACTVALUE\s*\(',
                r'\bOR\s+EXTRACTVALUE\s*\(',
                r'\bAND\s+UPDATEXML\s*\(',
                r'\bOR\s+UPDATEXML\s*\(',
                r'\bAND\s+extractvalue\s*\(',
                r'\bOR\s+extractvalue\s*\(',
                r'\bXPATH\s+error',
                r'\bsyntax\s+error',
                r'\bORA-\d+',
                r'\bMySQL\s+server',
                r'\bPostgreSQL\s+error',
            ],
            SQLInjectionType.BOOLEAN_BASED: [
                r'\bAND\s+\d+\s*=\s*\d+',
                r'\bOR\s+\d+\s*=\s*\d+',
                r'\bAND\s+TRUE\b',
                r'\bAND\s+FALSE\b',
                r'\bOR\s+TRUE\b',
                r'\bOR\s+FALSE\b',
                r'\bAND\s+1\s*=\s*1\b',
                r'\bAND\s+1\s*=\s*2\b',
                r'\bOR\s+1\s*=\s*1\b',
                r'\bOR\s+1\s*=\s*2\b',
            ],
            SQLInjectionType.TIME_BASED: [
                r'\bSLEEP\s*\(\s*\d+\s*\)',
                r'\bsleep\s*\(\s*\d+\s*\)',
                r'\bWAITFOR\s+DELAY',
                r'\bPG_SLEEP\s*\(',
                r'\bBENCHMARK\s*\(',
                r'\bAND\s+SLEEP\s*\(',
                r'\bOR\s+SLEEP\s*\(',
                r'\bAND\s+sleep\s*\(',
                r'\bOR\s+sleep\s*\(',
            ],
            SQLInjectionType.COMMENT: [
                r'--.*$',
                r'#.*$',
                r'/\*[\s\S]*?\*/',
                r';\s*--',
                r';\s*#',
            ],
            SQLInjectionType.STACKED_QUERIES: [
                r';\s*(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b',
                r';\s*(?:insert|update|delete|drop|create|alter)\b',
            ],
            SQLInjectionType.BLIND: [
                r'\bLIKE\s+[\'"]%',
                r'\bSUBSTRING\s*\(',
                r'\bASCII\s*\(',
                r'\bCHAR\s*\(',
                r'\bORD\s*\(',
                r'\bMID\s*\(',
                r'\bLEFT\s*\(',
                r'\bRIGHT\s*\(',
            ],
        }

    def detect(self, content: str, location: str = "unknown") -> List[SQLPayload]:
        payloads = []
        
        for injection_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    confidence = self._calculate_confidence(injection_type, match.group())
                    
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    payload = SQLPayload(
                        payload=match.group(),
                        injection_type=injection_type,
                        location=location,
                        confidence=confidence,
                        context=context
                    )
                    payloads.append(payload)
        
        return self._deduplicate_payloads(payloads)

    def _calculate_confidence(self, injection_type: SQLInjectionType, payload: str) -> float:
        base_confidence = {
            SQLInjectionType.UNION_BASED: 0.9,
            SQLInjectionType.ERROR_BASED: 0.85,
            SQLInjectionType.BOOLEAN_BASED: 0.7,
            SQLInjectionType.TIME_BASED: 0.95,
            SQLInjectionType.COMMENT: 0.5,
            SQLInjectionType.STACKED_QUERIES: 0.8,
            SQLInjectionType.BLIND: 0.75,
        }.get(injection_type, 0.5)

        indicators = [
            ('\'', 0.1),
            ('"', 0.1),
            ('--', 0.15),
            ('#', 0.1),
            ('UNION', 0.2),
            ('SELECT', 0.15),
            ('OR', 0.1),
            ('AND', 0.1),
        ]

        for indicator, weight in indicators:
            if indicator.lower() in payload.lower():
                base_confidence = min(1.0, base_confidence + weight)

        return round(base_confidence, 2)

    def _deduplicate_payloads(self, payloads: List[SQLPayload]) -> List[SQLPayload]:
        seen = set()
        unique_payloads = []
        
        for payload in payloads:
            key = (payload.payload, payload.injection_type, payload.location)
            if key not in seen:
                seen.add(key)
                unique_payloads.append(payload)
        
        return unique_payloads

    def analyze_http_session(self, session: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        payloads = []
        
        request = session.get('request')
        if request:
            uri = request.get('uri', '')
            body = request.get('body', '')
            headers = request.get('headers', {})
            raw = request.get('raw', '')

            uri_payloads = self.detect(uri, "URI")
            payloads.extend(uri_payloads)

            body_payloads = self.detect(body, "Body")
            payloads.extend(body_payloads)

            for header_name, header_value in headers.items():
                header_payloads = self.detect(header_value, f"Header:{header_name}")
                payloads.extend(header_payloads)

            raw_payloads = self.detect(raw, "Raw Request")
            payloads.extend(raw_payloads)

        if payloads:
            return VulnerabilityFinding(
                session_id=session.get('session_id', ''),
                source_ip=session.get('source_ip', ''),
                dest_ip=session.get('dest_ip', ''),
                url=request.get('uri', '') if request else '',
                method=request.get('method', '') if request else '',
                payloads=payloads,
                request_raw=request.get('raw', '') if request else '',
                response_raw=session.get('response', {}).get('raw', '') if session.get('response') else '',
                timestamp=session.get('start_time')
            )

        return None

    def analyze_sessions_file(self, file_path: str) -> List[VulnerabilityFinding]:
        with open(file_path, 'r', encoding='utf-8') as f:
            sessions = json.load(f)

        findings = []
        for session in sessions:
            finding = self.analyze_http_session(session)
            if finding:
                findings.append(finding)

        return findings

def finding_to_dict(finding: VulnerabilityFinding) -> Dict[str, Any]:
    return {
        'session_id': finding.session_id,
        'source_ip': finding.source_ip,
        'dest_ip': finding.dest_ip,
        'url': finding.url,
        'method': finding.method,
        'payloads': [
            {
                'payload': p.payload,
                'injection_type': p.injection_type.value,
                'location': p.location,
                'confidence': p.confidence,
                'context': p.context
            } for p in finding.payloads
        ],
        'request_raw': finding.request_raw,
        'response_raw': finding.response_raw,
        'timestamp': finding.timestamp,
        'severity': 'HIGH' if any(p.confidence > 0.8 for p in finding.payloads) else 'MEDIUM'
    }
