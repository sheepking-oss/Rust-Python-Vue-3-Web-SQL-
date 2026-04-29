import re
import json
import urllib.parse
import html
import base64
import binascii
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from urllib.parse import unquote, unquote_plus

class SQLInjectionType(Enum):
    UNION_BASED = "UNION-Based"
    ERROR_BASED = "Error-Based"
    BOOLEAN_BASED = "Boolean-Based"
    TIME_BASED = "Time-Based"
    BLIND = "Blind"
    COMMENT = "Comment"
    STACKED_QUERIES = "Stacked Queries"

class EncodingType(Enum):
    URL_ENCODED = "URL-Encoded"
    DOUBLE_URL_ENCODED = "Double URL-Encoded"
    TRIPLE_URL_ENCODED = "Triple URL-Encoded"
    HTML_ENTITY = "HTML Entity"
    UNICODE_ESCAPE = "Unicode Escape"
    HEX_ENCODED = "Hex Encoded"
    BASE64_ENCODED = "Base64 Encoded"
    UNICODE_URL_ENCODED = "Unicode URL-Encoded"

@dataclass
class SQLPayload:
    payload: str
    injection_type: SQLInjectionType
    location: str
    confidence: float
    context: str
    original_encoded: str
    encoding_type: Optional[EncodingType] = None
    decode_depth: int = 0

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

class EncodingDecoder:
    def __init__(self, max_decode_depth: int = 5):
        self.max_decode_depth = max_decode_depth
        self.url_special_chars = set("'\"\\/;=()[]{}|+&%$#@!^*-")
        
    def decode_all(self, content: str) -> List[Tuple[str, EncodingType, int]]:
        results = []
        seen = set()
        
        results.append((content, None, 0))
        seen.add(content)
        
        current_layer = [content]
        
        for depth in range(1, self.max_decode_depth + 1):
            next_layer = []
            
            for text in current_layer:
                decoded_list = self._decode_single_layer(text)
                
                for decoded, encoding_type in decoded_list:
                    if decoded and decoded not in seen and decoded != text:
                        seen.add(decoded)
                        results.append((decoded, encoding_type, depth))
                        next_layer.append(decoded)
            
            if not next_layer:
                break
            
            current_layer = next_layer
        
        return results
    
    def _decode_single_layer(self, text: str) -> List[Tuple[str, EncodingType]]:
        results = []
        
        url_decoded = self._url_decode(text)
        if url_decoded and url_decoded != text:
            results.append((url_decoded, EncodingType.URL_ENCODED))
        
        double_decoded = self._double_url_decode(text)
        if double_decoded and double_decoded != text and double_decoded != url_decoded:
            results.append((double_decoded, EncodingType.DOUBLE_URL_ENCODED))
        
        html_decoded = self._html_entity_decode(text)
        if html_decoded and html_decoded != text:
            results.append((html_decoded, EncodingType.HTML_ENTITY))
        
        unicode_decoded = self._unicode_escape_decode(text)
        if unicode_decoded and unicode_decoded != text:
            results.append((unicode_decoded, EncodingType.UNICODE_ESCAPE))
        
        hex_decoded = self._hex_decode(text)
        if hex_decoded and hex_decoded != text:
            results.append((hex_decoded, EncodingType.HEX_ENCODED))
        
        base64_decoded = self._base64_decode(text)
        if base64_decoded and base64_decoded != text:
            results.append((base64_decoded, EncodingType.BASE64_ENCODED))
        
        unicode_url_decoded = self._unicode_url_decode(text)
        if unicode_url_decoded and unicode_url_decoded != text:
            results.append((unicode_url_decoded, EncodingType.UNICODE_URL_ENCODED))
        
        return results
    
    def _url_decode(self, text: str) -> Optional[str]:
        try:
            decoded = unquote_plus(text)
            if decoded != text:
                return decoded
            decoded = unquote(text)
            if decoded != text:
                return decoded
        except (ValueError, TypeError):
            pass
        return None
    
    def _double_url_decode(self, text: str) -> Optional[str]:
        try:
            first_decode = unquote(text)
            if first_decode == text:
                return None
            second_decode = unquote(first_decode)
            if second_decode != first_decode:
                return second_decode
        except (ValueError, TypeError):
            pass
        return None
    
    def _html_entity_decode(self, text: str) -> Optional[str]:
        try:
            decoded = html.unescape(text)
            if decoded != text:
                return decoded
        except (ValueError, TypeError):
            pass
        return None
    
    def _unicode_escape_decode(self, text: str) -> Optional[str]:
        try:
            if '\\u' in text or '\\U' in text or '\\x' in text:
                decoded = text.encode('latin1').decode('unicode_escape')
                if decoded != text:
                    return decoded
        except (ValueError, TypeError, UnicodeDecodeError, UnicodeEncodeError):
            pass
        return None
    
    def _hex_decode(self, text: str) -> Optional[str]:
        hex_patterns = [
            (r'\b0x([0-9a-fA-F]+)\b', 1),
            (r'\b([0-9a-fA-F]{8,})\b', 0),
        ]
        
        for pattern, group in hex_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                hex_str = match.group(group) if group else match.group(0)
                if len(hex_str) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
                        if decoded and any(c in self.url_special_chars for c in decoded):
                            return decoded
                    except (ValueError, TypeError, binascii.Error):
                        pass
        return None
    
    def _base64_decode(self, text: str) -> Optional[str]:
        base64_pattern = r'^[A-Za-z0-9+/=]{8,}$|^[A-Za-z0-9_-]{8,}$'
        
        if re.match(base64_pattern, text.strip()):
            try:
                decoded = base64.b64decode(text.strip(), validate=True)
                decoded_str = decoded.decode('utf-8', errors='replace')
                if decoded_str and any(c in self.url_special_chars for c in decoded_str):
                    return decoded_str
            except (base64.binascii.Error, ValueError, UnicodeDecodeError):
                pass
        
        parts = re.findall(r'[A-Za-z0-9+/=]{16,}', text)
        for part in parts:
            try:
                decoded = base64.b64decode(part, validate=True)
                decoded_str = decoded.decode('utf-8', errors='replace')
                if decoded_str and any(c in self.url_special_chars for c in decoded_str):
                    return decoded_str
            except (base64.binascii.Error, ValueError, UnicodeDecodeError):
                pass
        
        return None
    
    def _unicode_url_decode(self, text: str) -> Optional[str]:
        unicode_url_pattern = r'%u([0-9a-fA-F]{4})'
        
        matches = re.findall(unicode_url_pattern, text)
        if matches:
            try:
                result = text
                for match in matches:
                    char_code = int(match, 16)
                    result = result.replace(f'%u{match}', chr(char_code))
                if result != text:
                    return result
            except (ValueError, TypeError):
                pass
        return None

class SQLInjectionDetector:
    def __init__(self, enable_encoding_detection: bool = True, max_decode_depth: int = 5):
        self.enable_encoding_detection = enable_encoding_detection
        self.decoder = EncodingDecoder(max_decode_depth=max_decode_depth)
        self.patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[SQLInjectionType, List[str]]:
        return {
            SQLInjectionType.UNION_BASED: [
                r'\bUNION\s+(?:ALL\s+)?SELECT\b',
                r'\bUNION\s+SELECT\b',
                r'\bSELECT\s+.*\s+FROM\b',
                r'\bUNION\s+DISTINCT\s+SELECT\b',
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
                r'\bUnclosed\s+quotation',
                r'\bInvalid\s+column\s+name',
                r'\bConversion\s+failed',
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
                r'\bAND\s+\'[^\']*\'\s*=\s*\'',
                r'\bOR\s+\'[^\']*\'\s*=\s*\'',
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
                r'\bIF\s*\(.*SLEEP',
                r'\bCASE\s+WHEN.*SLEEP',
            ],
            SQLInjectionType.COMMENT: [
                r'--.*$',
                r'#.*$',
                r'/\*[\s\S]*?\*/',
                r';\s*--',
                r';\s*#',
                r'\s+--\s*$',
            ],
            SQLInjectionType.STACKED_QUERIES: [
                r';\s*(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC)\b',
                r';\s*(?:insert|update|delete|drop|create|alter|truncate|exec)\b',
                r';\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+',
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
                r'\bSUBSTR\s*\(',
                r'\bLENGTH\s*\(',
                r'\bCHAR_LENGTH\s*\(',
                r'\bINSTR\s*\(',
                r'\bPOSITION\s*\(',
            ],
        }

    def detect(self, content: str, location: str = "unknown") -> List[SQLPayload]:
        payloads = []
        
        if self.enable_encoding_detection:
            decoded_variants = self.decoder.decode_all(content)
            
            for decoded_text, encoding_type, decode_depth in decoded_variants:
                found = self._detect_in_content(
                    decoded_text, 
                    location, 
                    content, 
                    encoding_type, 
                    decode_depth
                )
                payloads.extend(found)
        else:
            found = self._detect_in_content(content, location, content, None, 0)
            payloads.extend(found)
        
        return self._deduplicate_payloads(payloads)

    def _detect_in_content(
        self, 
        content: str, 
        location: str,
        original_content: str,
        encoding_type: Optional[EncodingType],
        decode_depth: int
    ) -> List[SQLPayload]:
        payloads = []
        
        for injection_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    confidence = self._calculate_confidence(
                        injection_type, 
                        match.group(),
                        encoding_type,
                        decode_depth
                    )
                    
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    payload = SQLPayload(
                        payload=match.group(),
                        injection_type=injection_type,
                        location=location,
                        confidence=confidence,
                        context=context,
                        original_encoded=original_content[
                            max(0, match.start() - 30):min(len(original_content), match.end() + 30)
                        ] if original_content != content else match.group(),
                        encoding_type=encoding_type,
                        decode_depth=decode_depth
                    )
                    payloads.append(payload)
        
        return payloads

    def _calculate_confidence(
        self, 
        injection_type: SQLInjectionType, 
        payload: str,
        encoding_type: Optional[EncodingType],
        decode_depth: int
    ) -> float:
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
            ('SLEEP', 0.25),
            ('EXTRACTVALUE', 0.2),
            ('UPDATEXML', 0.2),
        ]

        for indicator, weight in indicators:
            if indicator.lower() in payload.lower():
                base_confidence = min(1.0, base_confidence + weight)

        if encoding_type is not None:
            encoding_bonus = {
                EncodingType.DOUBLE_URL_ENCODED: 0.15,
                EncodingType.TRIPLE_URL_ENCODED: 0.2,
                EncodingType.UNICODE_URL_ENCODED: 0.15,
                EncodingType.BASE64_ENCODED: 0.1,
                EncodingType.HEX_ENCODED: 0.1,
                EncodingType.URL_ENCODED: 0.05,
                EncodingType.HTML_ENTITY: 0.05,
                EncodingType.UNICODE_ESCAPE: 0.1,
            }.get(encoding_type, 0.05)
            base_confidence = min(1.0, base_confidence + encoding_bonus)

        if decode_depth > 1:
            depth_bonus = min(0.15, decode_depth * 0.05)
            base_confidence = min(1.0, base_confidence + depth_bonus)

        return round(base_confidence, 2)

    def _deduplicate_payloads(self, payloads: List[SQLPayload]) -> List[SQLPayload]:
        seen = {}
        
        for payload in payloads:
            key = (
                payload.payload.lower(), 
                payload.injection_type, 
                payload.location,
                payload.encoding_type
            )
            
            if key not in seen:
                seen[key] = payload
            else:
                existing = seen[key]
                if payload.confidence > existing.confidence:
                    seen[key] = payload
        
        return list(seen.values())

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
                'context': p.context,
                'original_encoded': p.original_encoded,
                'encoding_type': p.encoding_type.value if p.encoding_type else None,
                'decode_depth': p.decode_depth
            } for p in finding.payloads
        ],
        'request_raw': finding.request_raw,
        'response_raw': finding.response_raw,
        'timestamp': finding.timestamp,
        'severity': 'HIGH' if any(p.confidence > 0.8 for p in finding.payloads) else 'MEDIUM'
    }

class TestEncodingDecoder:
    @staticmethod
    def test_url_decode():
        decoder = EncodingDecoder()
        
        encoded = "id=1%27%20UNION%20SELECT%201,2,3--"
        decoded_list = decoder.decode_all(encoded)
        
        found_sql_injection = False
        for decoded, encoding, depth in decoded_list:
            if 'UNION SELECT' in decoded.upper():
                found_sql_injection = True
                break
        
        return found_sql_injection

    @staticmethod
    def test_double_url_decode():
        decoder = EncodingDecoder()
        
        double_encoded = "id=1%2527%2520UNION%2520SELECT%25201,2,3--"
        decoded_list = decoder.decode_all(double_encoded)
        
        found_sql_injection = False
        for decoded, encoding, depth in decoded_list:
            if 'UNION SELECT' in decoded.upper():
                found_sql_injection = True
                break
        
        return found_sql_injection

    @staticmethod
    def test_html_entity_decode():
        decoder = EncodingDecoder()
        
        html_encoded = "id=1&#39; UNION SELECT 1,2,3--"
        decoded_list = decoder.decode_all(html_encoded)
        
        found_sql_injection = False
        for decoded, encoding, depth in decoded_list:
            if 'UNION SELECT' in decoded.upper():
                found_sql_injection = True
                break
        
        return found_sql_injection

    @staticmethod
    def test_unicode_escape():
        decoder = EncodingDecoder()
        
        unicode_encoded = r"id=1\u0027 UNION SELECT 1,2,3--"
        decoded_list = decoder.decode_all(unicode_encoded)
        
        found_sql_injection = False
        for decoded, encoding, depth in decoded_list:
            if 'UNION SELECT' in decoded.upper():
                found_sql_injection = True
                break
        
        return found_sql_injection

if __name__ == "__main__":
    print("Testing Encoding Decoder...")
    
    print(f"URL Decode Test: {TestEncodingDecoder.test_url_decode()}")
    print(f"Double URL Decode Test: {TestEncodingDecoder.test_double_url_decode()}")
    print(f"HTML Entity Decode Test: {TestEncodingDecoder.test_html_entity_decode()}")
    print(f"Unicode Escape Test: {TestEncodingDecoder.test_unicode_escape()}")
    
    print("\nTesting SQL Injection Detection with Encoded Payloads...")
    
    detector = SQLInjectionDetector(enable_encoding_detection=True)
    
    test_cases = [
        ("id=1' UNION SELECT 1,2,3--", "Plain SQL Injection"),
        ("id=1%27%20UNION%20SELECT%201,2,3--", "URL Encoded"),
        ("id=1%2527%2520UNION%2520SELECT%25201,2,3--", "Double URL Encoded"),
        ("id=1&#39; UNION SELECT 1,2,3--", "HTML Entity Encoded"),
        ("id=1%252527%252520UNION%252520SELECT", "Triple URL Encoded"),
    ]
    
    for payload, description in test_cases:
        results = detector.detect(payload, "URI")
        print(f"\n{description}:")
        print(f"  Payload: {payload[:60]}...")
        print(f"  Detected payloads: {len(results)}")
        for r in results:
            enc_type = r.encoding_type.value if r.encoding_type else "None"
            print(f"    - {r.injection_type.value}: '{r.payload[:30]}...' (conf: {r.confidence}, encoding: {enc_type}, depth: {r.decode_depth})")
