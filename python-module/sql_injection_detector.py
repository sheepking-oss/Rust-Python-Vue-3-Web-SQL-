import re
import json
import urllib.parse
import html
import base64
import binascii
import hashlib
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import unquote, unquote_plus
from collections import OrderedDict

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
    DOUBLE_HTML_ENTITY = "Double HTML Entity"
    UNICODE_ESCAPE = "Unicode Escape"
    UNICODE_URL = "Unicode URL (%u)"
    HEX_ENCODED = "Hex Encoded"
    HEX_STRING = "Hex String (0x)"
    BASE64_ENCODED = "Base64 Encoded"
    OCTAL_ENCODED = "Octal Encoded"
    MIXED_ENCODING = "Mixed Encoding"
    URL_PLUS_ENCODED = "URL+ Encoded (space as +)"
    PERCENT_UPPER = "Percent Upper (%25)"
    PERCENT_LOWER = "Percent Lower (%3d)"

@dataclass
class DecodeResult:
    decoded_text: str
    encoding_type: Optional[EncodingType]
    decode_depth: int
    decode_path: List[EncodingType] = field(default_factory=list)
    original_text: str = ""

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
    decode_path: List[EncodingType] = field(default_factory=list)

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

class EncodingDetector:
    URL_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
    UNICODE_URL_PATTERN = re.compile(r'%u[0-9a-fA-F]{4}')
    HEX_PATTERN = re.compile(r'\\x[0-9a-fA-F]{2}')
    UNICODE_ESCAPE_PATTERN = re.compile(r'\\u[0-9a-fA-F]{4}')
    OCTAL_PATTERN = re.compile(r'\\[0-7]{3}')
    HTML_ENTITY_PATTERN = re.compile(r'&#[0-9]+;|&#x[0-9a-fA-F]+;|&[a-zA-Z]+;')
    HEX_STRING_PATTERN = re.compile(r'0x[0-9a-fA-F]+')
    BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    URL_SAFE_BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=')
    
    SQL_SPECIAL_CHARS = set("'\"\\/;=()[]{}|+&%$#@!^*-<>")
    SQL_KEYWORDS = {'UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 
                    'LIKE', 'ORDER', 'GROUP', 'BY', 'HAVING', 'JOIN', 'LEFT', 
                    'RIGHT', 'INNER', 'OUTER', 'FULL', 'ON', 'AS', 'DISTINCT',
                    'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
                    'TABLE', 'DATABASE', 'INDEX', 'VIEW', 'TRIGGER',
                    'SLEEP', 'BENCHMARK', 'EXTRACTVALUE', 'UPDATEXML',
                    'SUBSTRING', 'SUBSTR', 'ASCII', 'CHAR', 'ORD', 'MID',
                    'LEFT', 'RIGHT', 'LENGTH', 'CHAR_LENGTH', 'INSTR', 'POSITION'}
    
    @classmethod
    def detect_encoding(cls, text: str) -> List[Tuple[EncodingType, float]]:
        results = []
        
        url_count = len(cls.URL_PATTERN.findall(text))
        if url_count > 0:
            url_ratio = url_count / max(1, len(text) / 3)
            if '%25' in text or '%25' in text.upper():
                double_count = text.upper().count('%25')
                if double_count > url_count / 2:
                    results.append((EncodingType.DOUBLE_URL_ENCODED, 0.9))
                else:
                    results.append((EncodingType.DOUBLE_URL_ENCODED, 0.6))
                    results.append((EncodingType.URL_ENCODED, 0.8))
            else:
                results.append((EncodingType.URL_ENCODED, min(0.9, url_ratio + 0.3)))
        
        if '+' in text and ('%20' not in text):
            words = text.split('+')
            if len(words) > 1 and all(len(w) > 0 for w in words):
                results.append((EncodingType.URL_PLUS_ENCODED, 0.7))
        
        unicode_url_count = len(cls.UNICODE_URL_PATTERN.findall(text))
        if unicode_url_count > 0:
            results.append((EncodingType.UNICODE_URL, 0.9))
        
        hex_escape_count = len(cls.HEX_PATTERN.findall(text))
        if hex_escape_count > 0:
            results.append((EncodingType.HEX_ENCODED, 0.85))
        
        unicode_escape_count = len(cls.UNICODE_ESCAPE_PATTERN.findall(text))
        if unicode_escape_count > 0:
            results.append((EncodingType.UNICODE_ESCAPE, 0.9))
        
        octal_count = len(cls.OCTAL_PATTERN.findall(text))
        if octal_count > 0:
            results.append((EncodingType.OCTAL_ENCODED, 0.85))
        
        html_entity_count = len(cls.HTML_ENTITY_PATTERN.findall(text))
        if html_entity_count > 0:
            if '&amp;' in text:
                results.append((EncodingType.DOUBLE_HTML_ENTITY, 0.8))
            results.append((EncodingType.HTML_ENTITY, 0.85))
        
        hex_string_match = cls.HEX_STRING_PATTERN.search(text)
        if hex_string_match:
            results.append((EncodingType.HEX_STRING, 0.8))
        
        base64_score = cls._score_base64(text)
        if base64_score > 0.6:
            results.append((EncodingType.BASE64_ENCODED, base64_score))
        
        results.sort(key=lambda x: x[1], reverse=True)
        return results
    
    @classmethod
    def _score_base64(cls, text: str) -> float:
        if len(text) < 8:
            return 0.0
        
        stripped = text.strip()
        
        valid_chars = all(c in cls.BASE64_CHARS for c in stripped)
        valid_url_safe = all(c in cls.URL_SAFE_BASE64_CHARS for c in stripped)
        
        if not (valid_chars or valid_url_safe):
            return 0.0
        
        if len(stripped) % 4 != 0:
            return 0.3
        
        equals_count = stripped.count('=')
        if equals_count > 2:
            return 0.3
        
        if equals_count > 0 and not stripped.endswith('='):
            return 0.4
        
        upper_ratio = sum(1 for c in stripped if c.isupper()) / max(1, len(stripped) - equals_count)
        lower_ratio = sum(1 for c in stripped if c.islower()) / max(1, len(stripped) - equals_count)
        
        if 0.2 < upper_ratio < 0.8 and 0.2 < lower_ratio < 0.8:
            return 0.85
        
        return 0.6
    
    @classmethod
    def has_sql_indicators(cls, text: str) -> bool:
        text_upper = text.upper()
        
        for char in cls.SQL_SPECIAL_CHARS:
            if char in text:
                return True
        
        for keyword in cls.SQL_KEYWORDS:
            if f' {keyword} ' in text_upper or f'{keyword}(' in text_upper:
                return True
        
        return False
    
    @classmethod
    def calculate_decode_necessity(cls, text: str) -> float:
        score = 0.0
        
        if cls.has_sql_indicators(text):
            score += 0.3
        
        if '%' in text:
            url_count = len(cls.URL_PATTERN.findall(text))
            score += min(0.4, url_count * 0.05)
        
        if '&#' in text or '&' in text:
            html_count = len(cls.HTML_ENTITY_PATTERN.findall(text))
            score += min(0.4, html_count * 0.05)
        
        if '\\x' in text or '\\u' in text:
            score += 0.3
        
        if '+' in text and len(text.split('+')) > 2:
            score += 0.2
        
        return min(1.0, score)

class AdvancedDecoder:
    MAX_DECODE_DEPTH = 8
    MAX_DECODE_ATTEMPTS = 50
    
    def __init__(self):
        self.decoded_cache: Dict[str, List[DecodeResult]] = {}
        self.seen_texts: Set[str] = set()
    
    def decode_all(self, text: str) -> List[DecodeResult]:
        if not text:
            return []
        
        if text in self.decoded_cache:
            return self.decoded_cache[text]
        
        self.seen_texts.clear()
        results = []
        
        results.append(DecodeResult(
            decoded_text=text,
            encoding_type=None,
            decode_depth=0,
            decode_path=[],
            original_text=text
        ))
        self.seen_texts.add(text)
        
        self._recursive_decode(
            text, 
            [], 
            0, 
            results
        )
        
        results = self._deduplicate_results(results)
        
        self.decoded_cache[text] = results
        return results
    
    def _recursive_decode(
        self, 
        text: str, 
        current_path: List[EncodingType], 
        current_depth: int,
        results: List[DecodeResult]
    ):
        if current_depth >= self.MAX_DECODE_DEPTH:
            return
        
        if len(results) > self.MAX_DECODE_ATTEMPTS:
            return
        
        detected = EncodingDetector.detect_encoding(text)
        
        for encoding_type, confidence in detected:
            if confidence < 0.3:
                continue
            
            decoded = self._decode_by_type(text, encoding_type)
            
            if decoded and decoded != text and decoded not in self.seen_texts:
                self.seen_texts.add(decoded)
                
                new_path = current_path + [encoding_type]
                
                result = DecodeResult(
                    decoded_text=decoded,
                    encoding_type=encoding_type,
                    decode_depth=current_depth + 1,
                    decode_path=new_path.copy(),
                    original_text=text
                )
                results.append(result)
                
                if EncodingDetector.calculate_decode_necessity(decoded) > 0.2:
                    self._recursive_decode(
                        decoded, 
                        new_path, 
                        current_depth + 1, 
                        results
                    )
        
        if '%' in text or '+' in text:
            decoded = self._url_decode_full(text)
            if decoded and decoded != text and decoded not in self.seen_texts:
                self.seen_texts.add(decoded)
                
                encoding = EncodingType.URL_ENCODED if '%' in text else EncodingType.URL_PLUS_ENCODED
                new_path = current_path + [encoding]
                
                result = DecodeResult(
                    decoded_text=decoded,
                    encoding_type=encoding,
                    decode_depth=current_depth + 1,
                    decode_path=new_path.copy(),
                    original_text=text
                )
                results.append(result)
                
                if EncodingDetector.calculate_decode_necessity(decoded) > 0.2:
                    self._recursive_decode(
                        decoded, 
                        new_path, 
                        current_depth + 1, 
                        results
                    )
    
    def _decode_by_type(self, text: str, encoding_type: EncodingType) -> Optional[str]:
        try:
            if encoding_type == EncodingType.URL_ENCODED:
                return self._url_decode_full(text)
            
            elif encoding_type == EncodingType.URL_PLUS_ENCODED:
                return unquote_plus(text)
            
            elif encoding_type == EncodingType.DOUBLE_URL_ENCODED:
                first = unquote(text)
                if first != text:
                    second = unquote(first)
                    return second
                return None
            
            elif encoding_type == EncodingType.TRIPLE_URL_ENCODED:
                result = text
                for _ in range(3):
                    decoded = unquote(result)
                    if decoded == result:
                        break
                    result = decoded
                return result if result != text else None
            
            elif encoding_type == EncodingType.HTML_ENTITY:
                return html.unescape(text)
            
            elif encoding_type == EncodingType.DOUBLE_HTML_ENTITY:
                first = html.unescape(text)
                if first != text:
                    second = html.unescape(first)
                    return second
                return None
            
            elif encoding_type == EncodingType.UNICODE_ESCAPE:
                return self._unicode_escape_decode(text)
            
            elif encoding_type == EncodingType.UNICODE_URL:
                return self._unicode_url_decode(text)
            
            elif encoding_type == EncodingType.HEX_ENCODED:
                return self._hex_escape_decode(text)
            
            elif encoding_type == EncodingType.HEX_STRING:
                return self._hex_string_decode(text)
            
            elif encoding_type == EncodingType.BASE64_ENCODED:
                return self._base64_decode_full(text)
            
            elif encoding_type == EncodingType.OCTAL_ENCODED:
                return self._octal_decode(text)
            
            elif encoding_type == EncodingType.MIXED_ENCODING:
                return self._mixed_decode(text)
            
            return None
            
        except Exception:
            return None
    
    def _url_decode_full(self, text: str) -> str:
        result = text
        changed = True
        iterations = 0
        
        while changed and iterations < 10:
            iterations += 1
            new_result = unquote(result)
            if new_result == result:
                new_result = unquote_plus(result)
            if new_result == result:
                changed = False
            else:
                result = new_result
        
        return result
    
    def _unicode_escape_decode(self, text: str) -> Optional[str]:
        try:
            if '\\u' not in text and '\\x' not in text and '\\U' not in text:
                return None
            
            result = text
            
            result = re.sub(
                r'\\u([0-9a-fA-F]{4})',
                lambda m: chr(int(m.group(1), 16)),
                result
            )
            
            result = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                result
            )
            
            result = re.sub(
                r'\\U([0-9a-fA-F]{8})',
                lambda m: chr(int(m.group(1), 16)),
                result
            )
            
            return result if result != text else None
            
        except Exception:
            return None
    
    def _unicode_url_decode(self, text: str) -> Optional[str]:
        try:
            if '%u' not in text and '%U' not in text:
                return None
            
            result = re.sub(
                r'%u([0-9a-fA-F]{4})',
                lambda m: chr(int(m.group(1), 16)),
                text,
                flags=re.IGNORECASE
            )
            
            return result if result != text else None
            
        except Exception:
            return None
    
    def _hex_escape_decode(self, text: str) -> Optional[str]:
        try:
            if '\\x' not in text and '\\X' not in text:
                return None
            
            result = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                text,
                flags=re.IGNORECASE
            )
            
            return result if result != text else None
            
        except Exception:
            return None
    
    def _hex_string_decode(self, text: str) -> Optional[str]:
        try:
            matches = re.findall(r'0x([0-9a-fA-F]+)', text, re.IGNORECASE)
            if not matches:
                return None
            
            result = text
            for hex_str in matches:
                if len(hex_str) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
                        result = result.replace(f'0x{hex_str}', decoded)
                        result = result.replace(f'0X{hex_str}', decoded)
                    except Exception:
                        pass
            
            return result if result != text else None
            
        except Exception:
            return None
    
    def _base64_decode_full(self, text: str) -> Optional[str]:
        try:
            stripped = text.strip()
            
            padding_needed = 4 - (len(stripped) % 4)
            if padding_needed != 4:
                stripped += '=' * padding_needed
            
            try:
                decoded = base64.b64decode(stripped, validate=True)
            except Exception:
                try:
                    decoded = base64.b64decode(stripped.replace('-', '+').replace('_', '/'), validate=True)
                except Exception:
                    decoded = base64.b64decode(stripped, validate=False)
            
            try:
                result = decoded.decode('utf-8')
            except UnicodeDecodeError:
                result = decoded.decode('latin1')
            
            if EncodingDetector.has_sql_indicators(result):
                return result
            
            if len(result) > 0 and all(32 <= ord(c) < 127 for c in result):
                return result
            
            return None
            
        except Exception:
            return None
    
    def _octal_decode(self, text: str) -> Optional[str]:
        try:
            if '\\' not in text:
                return None
            
            result = re.sub(
                r'\\([0-7]{3})',
                lambda m: chr(int(m.group(1), 8)),
                text
            )
            
            return result if result != text else None
            
        except Exception:
            return None
    
    def _mixed_decode(self, text: str) -> Optional[str]:
        try:
            result = text
            
            result = html.unescape(result)
            
            result = unquote_plus(result)
            
            result = re.sub(
                r'%u([0-9a-fA-F]{4})',
                lambda m: chr(int(m.group(1), 16)),
                result,
                flags=re.IGNORECASE
            )
            
            result = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                result,
                flags=re.IGNORECASE
            )
            
            result = re.sub(
                r'\\u([0-9a-fA-F]{4})',
                lambda m: chr(int(m.group(1), 16)),
                result
            )
            
            return result if result != text else None
            
        except Exception:
            return None
    
    def _deduplicate_results(self, results: List[DecodeResult]) -> List[DecodeResult]:
        seen = {}
        
        for result in results:
            key = result.decoded_text
            
            if key not in seen:
                seen[key] = result
            else:
                existing = seen[key]
                
                if len(result.decode_path) > len(existing.decode_path):
                    seen[key] = result
                elif len(result.decode_path) == len(existing.decode_path):
                    if result.decode_depth < existing.decode_depth:
                        seen[key] = result
        
        final_results = list(seen.values())
        
        final_results.sort(key=lambda x: (
            -len(x.decode_path),
            x.decode_depth,
            -EncodingDetector.calculate_decode_necessity(x.decoded_text)
        ))
        
        return final_results

class SQLInjectionDetector:
    def __init__(self, enable_encoding_detection: bool = True, max_decode_depth: int = 8):
        self.enable_encoding_detection = enable_encoding_detection
        self.decoder = AdvancedDecoder()
        self.patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[SQLInjectionType, List[str]]:
        return {
            SQLInjectionType.UNION_BASED: [
                r'\bUNION\s+(?:ALL\s+)?(?:DISTINCT\s+)?SELECT\b',
                r'\bUNION\s+SELECT\b',
                r'\bSELECT\s+.*?\s+FROM\b',
                r'\bUNION\s+DISTINCT\s+SELECT\b',
                r'\bUNION\s+ALL\s+SELECT\b',
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
                r'\bYou\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax',
            ],
            SQLInjectionType.BOOLEAN_BASED: [
                r'\bAND\s+\d+\s*=\s*\d+\b',
                r'\bOR\s+\d+\s*=\s*\d+\b',
                r'\bAND\s+TRUE\b',
                r'\bAND\s+FALSE\b',
                r'\bOR\s+TRUE\b',
                r'\bOR\s+FALSE\b',
                r'\bAND\s+1\s*=\s*1\b',
                r'\bAND\s+1\s*=\s*2\b',
                r'\bOR\s+1\s*=\s*1\b',
                r'\bOR\s+1\s*=\s*2\b',
                r"\bAND\s+'[^']*'\s*=\s*'",
                r"\bOR\s+'[^']*'\s*=\s*'",
                r'\bAND\s+"[^"]*"\s*=\s*"',
                r'\bOR\s+"[^"]*"\s*=\s*"',
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
                r'\bWAITFOR\s+TIME',
                r'\bDELAY\s*\(',
            ],
            SQLInjectionType.COMMENT: [
                r'--.*$',
                r'#.*$',
                r'/\*[\s\S]*?\*/',
                r';\s*--',
                r';\s*#',
                r'\s+--\s*$',
                r'--\s*$',
                r'#\s*$',
            ],
            SQLInjectionType.STACKED_QUERIES: [
                r';\s*(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|GRANT|REVOKE)\b',
                r';\s*(?:insert|update|delete|drop|create|alter|truncate|exec|grant|revoke)\b',
                r';\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+',
                r';\s*SHUTDOWN\b',
                r';\s*BACKUP\s+DATABASE\b',
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
                r'\bLOCATE\s*\(',
                r'\bSTRCMP\s*\(',
                r'\bstrcmp\s*\(',
            ],
        }

    def detect(self, content: str, location: str = "unknown") -> List[SQLPayload]:
        payloads = []
        
        if not content or len(content) < 3:
            return payloads
        
        if self.enable_encoding_detection:
            decode_necessity = EncodingDetector.calculate_decode_necessity(content)
            
            if decode_necessity > 0.1:
                decoded_variants = self.decoder.decode_all(content)
                
                for decoded_result in decoded_variants:
                    found = self._detect_in_content(
                        decoded_result.decoded_text, 
                        location, 
                        content,
                        decoded_result.encoding_type,
                        decoded_result.decode_depth,
                        decoded_result.decode_path
                    )
                    payloads.extend(found)
            else:
                found = self._detect_in_content(content, location, content, None, 0, [])
                payloads.extend(found)
        else:
            found = self._detect_in_content(content, location, content, None, 0, [])
            payloads.extend(found)
        
        return self._deduplicate_payloads(payloads)

    def _detect_in_content(
        self, 
        content: str, 
        location: str,
        original_content: str,
        encoding_type: Optional[EncodingType],
        decode_depth: int,
        decode_path: List[EncodingType]
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
                        decode_depth,
                        decode_path
                    )
                    
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').replace('\r', ' ').strip()
                    
                    orig_start = max(0, match.start() - 30)
                    orig_end = min(len(original_content), match.end() + 30)
                    original_encoded = original_content[orig_start:orig_end] if original_content != content else match.group()
                    
                    payload = SQLPayload(
                        payload=match.group(),
                        injection_type=injection_type,
                        location=location,
                        confidence=confidence,
                        context=context,
                        original_encoded=original_encoded,
                        encoding_type=encoding_type,
                        decode_depth=decode_depth,
                        decode_path=decode_path.copy() if decode_path else []
                    )
                    payloads.append(payload)
        
        return payloads

    def _calculate_confidence(
        self, 
        injection_type: SQLInjectionType, 
        payload: str,
        encoding_type: Optional[EncodingType],
        decode_depth: int,
        decode_path: List[EncodingType]
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
            ('DROP', 0.2),
            ('DELETE', 0.15),
        ]

        for indicator, weight in indicators:
            if indicator.lower() in payload.lower():
                base_confidence = min(1.0, base_confidence + weight)

        if encoding_type is not None:
            encoding_bonus = {
                EncodingType.TRIPLE_URL_ENCODED: 0.25,
                EncodingType.DOUBLE_URL_ENCODED: 0.2,
                EncodingType.DOUBLE_HTML_ENTITY: 0.2,
                EncodingType.UNICODE_URL: 0.2,
                EncodingType.BASE64_ENCODED: 0.15,
                EncodingType.HEX_STRING: 0.15,
                EncodingType.MIXED_ENCODING: 0.2,
                EncodingType.UNICODE_ESCAPE: 0.15,
                EncodingType.URL_ENCODED: 0.1,
                EncodingType.HTML_ENTITY: 0.1,
                EncodingType.HEX_ENCODED: 0.1,
                EncodingType.URL_PLUS_ENCODED: 0.1,
            }.get(encoding_type, 0.05)
            base_confidence = min(1.0, base_confidence + encoding_bonus)

        if decode_path:
            path_bonus = 0.0
            for enc in decode_path:
                if enc in [EncodingType.DOUBLE_URL_ENCODED, EncodingType.TRIPLE_URL_ENCODED, 
                          EncodingType.DOUBLE_HTML_ENTITY, EncodingType.MIXED_ENCODING]:
                    path_bonus += 0.1
            base_confidence = min(1.0, base_confidence + path_bonus)

        if decode_depth > 1:
            depth_bonus = min(0.2, decode_depth * 0.04)
            base_confidence = min(1.0, base_confidence + depth_bonus)

        return round(base_confidence, 2)

    def _deduplicate_payloads(self, payloads: List[SQLPayload]) -> List[SQLPayload]:
        seen = {}
        
        for payload in payloads:
            key = (
                payload.payload.lower(), 
                payload.injection_type, 
                payload.location,
                tuple(payload.decode_path) if payload.decode_path else None
            )
            
            if key not in seen:
                seen[key] = payload
            else:
                existing = seen[key]
                if payload.confidence > existing.confidence:
                    seen[key] = payload
                elif payload.confidence == existing.confidence:
                    if len(payload.decode_path) > len(existing.decode_path):
                        seen[key] = payload
        
        unique_payloads = list(seen.values())
        
        unique_payloads.sort(key=lambda x: (
            -x.confidence,
            -len(x.decode_path),
            x.decode_depth
        ))
        
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
                'context': p.context,
                'original_encoded': p.original_encoded,
                'encoding_type': p.encoding_type.value if p.encoding_type else None,
                'decode_depth': p.decode_depth,
                'decode_path': [enc.value for enc in p.decode_path] if p.decode_path else []
            } for p in finding.payloads
        ],
        'request_raw': finding.request_raw,
        'response_raw': finding.response_raw,
        'timestamp': finding.timestamp,
        'severity': 'HIGH' if any(p.confidence > 0.8 for p in finding.payloads) else 'MEDIUM'
    }

class TestAdvancedDecoder:
    @staticmethod
    def test_all_encodings():
        decoder = AdvancedDecoder()
        detector = SQLInjectionDetector(enable_encoding_detection=True)
        
        test_cases = [
            ("id=1' UNION SELECT 1,2,3--", "Plain Text", None),
            ("id=1%27%20UNION%20SELECT%201,2,3--", "URL Encoded", EncodingType.URL_ENCODED),
            ("id=1%2527%2520UNION%2520SELECT%25201,2,3--", "Double URL Encoded", EncodingType.DOUBLE_URL_ENCODED),
            ("id=1%252527%252520UNION%252520SELECT%2525201,2,3--", "Triple URL Encoded", EncodingType.TRIPLE_URL_ENCODED),
            ("id=1&#39; UNION SELECT 1,2,3--", "HTML Entity", EncodingType.HTML_ENTITY),
            ("id=1&amp;#39; UNION SELECT 1,2,3--", "Double HTML Entity", EncodingType.DOUBLE_HTML_ENTITY),
            ("id=1\\u0027 UNION SELECT 1,2,3--", "Unicode Escape", EncodingType.UNICODE_ESCAPE),
            ("id=1%u0027 UNION SELECT 1,2,3--", "Unicode URL", EncodingType.UNICODE_URL),
            ("id=1\\x27 UNION SELECT 1,2,3--", "Hex Escape", EncodingType.HEX_ENCODED),
            ("id=1'+UNION+SELECT+1,2,3--", "URL+ Encoded", EncodingType.URL_PLUS_ENCODED),
        ]
        
        print("=" * 80)
        print("Testing Advanced Encoding Decoder")
        print("=" * 80)
        
        all_passed = True
        for payload, description, expected_encoding in test_cases:
            print(f"\n{description}:")
            print(f"  Input: {payload[:80]}...")
            
            decoded = decoder.decode_all(payload)
            print(f"  Decoded variants: {len(decoded)}")
            
            results = detector.detect(payload, "URI")
            
            found_sql = False
            for r in results:
                if 'UNION' in r.payload.upper() or 'SELECT' in r.payload.upper():
                    found_sql = True
                    enc_type = r.encoding_type.value if r.encoding_type else "None"
                    print(f"    [OK] Detected: {r.payload[:40]}... (conf: {r.confidence}, encoding: {enc_type}, depth: {r.decode_depth})")
                    if r.decode_path:
                        print(f"          Decode path: {' -> '.join([e.value for e in r.decode_path])}")
            
            if not found_sql:
                print(f"    [FAIL] SQL injection not detected!")
                all_passed = False
        
        print("\n" + "=" * 80)
        print(f"Overall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
        print("=" * 80)
        
        return all_passed
    
    @staticmethod
    def test_mixed_encodings():
        decoder = AdvancedDecoder()
        detector = SQLInjectionDetector(enable_encoding_detection=True)
        
        mixed_test_cases = [
            ("id=1%2527%2520AND%2520SLEEP%25285%2529--", "Double URL + Sleep"),
            ("id=1&#39;%20UNION%20SELECT%201,2,3--", "HTML Entity + URL"),
            ("id=1%2526%252339%253B%2520UNION%2520SELECT", "Double URL + Double HTML Entity"),
            ("id=1%u0027%20AND%201=1--", "Unicode URL + URL"),
        ]
        
        print("\n" + "=" * 80)
        print("Testing Mixed Encodings")
        print("=" * 80)
        
        all_passed = True
        for payload, description in mixed_test_cases:
            print(f"\n{description}:")
            print(f"  Input: {payload[:80]}...")
            
            decoded = decoder.decode_all(payload)
            print(f"  Decoded variants: {len(decoded)}")
            
            results = detector.detect(payload, "URI")
            
            found = False
            for r in results:
                if 'UNION' in r.payload.upper() or 'SLEEP' in r.payload.upper() or 'AND' in r.payload.upper():
                    found = True
                    enc_type = r.encoding_type.value if r.encoding_type else "None"
                    print(f"    [OK] Detected: {r.payload[:40]}... (conf: {r.confidence}, encoding: {enc_type}, depth: {r.decode_depth})")
                    if r.decode_path:
                        print(f"          Decode path: {' -> '.join([e.value for e in r.decode_path])}")
            
            if not found:
                print(f"    [FAIL] Attack not detected!")
                all_passed = False
        
        return all_passed

if __name__ == "__main__":
    print("=" * 80)
    print("Advanced Encoding Decoder Test Suite")
    print("=" * 80)
    
    result1 = TestAdvancedDecoder.test_all_encodings()
    result2 = TestAdvancedDecoder.test_mixed_encodings()
    
    print("\n" + "=" * 80)
    if result1 and result2:
        print("FINAL RESULT: ALL TESTS PASSED [OK]")
    else:
        print("FINAL RESULT: SOME TESTS FAILED [FAIL]")
    print("=" * 80)
