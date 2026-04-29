use super::{HTTPSession, HTTPRequest, HTTPResponse, PacketInfo};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StreamKey {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

impl StreamKey {
    fn reverse(&self) -> Self {
        StreamKey {
            src_ip: self.dst_ip.clone(),
            src_port: self.dst_port,
            dst_ip: self.src_ip.clone(),
            dst_port: self.src_port,
        }
    }
    
    fn normalize(&self) -> (Self, bool) {
        let key1 = format!("{}:{}", self.src_ip, self.src_port);
        let key2 = format!("{}:{}", self.dst_ip, self.dst_port);
        
        if key1 > key2 {
            (self.reverse(), true)
        } else {
            (self.clone(), false)
        }
    }
}

#[derive(Debug, Clone)]
struct TcpSegment {
    seq: u32,
    payload: Vec<u8>,
    length: usize,
    next_seq: u32,
}

#[derive(Debug, Clone, Default)]
struct TcpStreamBuffer {
    segments: BTreeMap<u32, TcpSegment>,
    received_seqs: HashSet<u32>,
    base_seq: Option<u32>,
    expected_seq: Option<u32>,
}

impl TcpStreamBuffer {
    fn new() -> Self {
        TcpStreamBuffer {
            segments: BTreeMap::new(),
            received_seqs: HashSet::new(),
            base_seq: None,
            expected_seq: None,
        }
    }
    
    fn add_segment(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        
        let length = payload.len();
        let next_seq = seq.wrapping_add(length as u32);
        
        if self.received_seqs.contains(&seq) {
            return;
        }
        
        let segment = TcpSegment {
            seq,
            payload: payload.to_vec(),
            length,
            next_seq,
        };
        
        self.segments.insert(seq, segment);
        self.received_seqs.insert(seq);
        
        if self.base_seq.is_none() {
            self.base_seq = Some(seq);
            self.expected_seq = Some(next_seq);
        }
    }
    
    fn reassemble(&mut self) -> Vec<u8> {
        if self.segments.is_empty() {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        let mut current_pos: Option<u32> = None;
        
        let segments: Vec<&TcpSegment> = self.segments.values().collect();
        
        for segment in segments {
            if current_pos.is_none() {
                current_pos = Some(segment.seq);
                result.extend_from_slice(&segment.payload);
                current_pos = Some(segment.next_seq);
            } else {
                let curr = current_pos.unwrap();
                
                if segment.seq == curr {
                    result.extend_from_slice(&segment.payload);
                    current_pos = Some(segment.next_seq);
                } else if is_seq_less_than(segment.seq, curr) {
                    if is_seq_greater_than(segment.next_seq, curr) {
                        let overlap = curr.wrapping_sub(segment.seq) as usize;
                        if overlap < segment.payload.len() {
                            result.extend_from_slice(&segment.payload[overlap..]);
                            current_pos = Some(segment.next_seq);
                        }
                    }
                }
            }
        }
        
        result
    }
    
    fn has_complete_data(&self) -> bool {
        if self.segments.is_empty() {
            return false;
        }
        
        let mut expected_seq: Option<u32> = None;
        
        for (seq, segment) in &self.segments {
            if expected_seq.is_none() {
                expected_seq = Some(segment.next_seq);
            } else {
                if *seq != expected_seq.unwrap() {
                    return false;
                }
                expected_seq = Some(segment.next_seq);
            }
        }
        
        true
    }
}

fn is_seq_less_than(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn is_seq_greater_than(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[derive(Debug, Clone)]
struct HttpRequestState {
    method: Option<String>,
    uri: Option<String>,
    version: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    raw: Vec<u8>,
    headers_complete: bool,
    content_length: Option<usize>,
    is_chunked: bool,
}

impl HttpRequestState {
    fn new() -> Self {
        HttpRequestState {
            method: None,
            uri: None,
            version: None,
            headers: HashMap::new(),
            body: Vec::new(),
            raw: Vec::new(),
            headers_complete: false,
            content_length: None,
            is_chunked: false,
        }
    }
}

#[derive(Debug, Clone)]
struct HttpResponseState {
    version: Option<String>,
    status_code: Option<u16>,
    status_text: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    raw: Vec<u8>,
    headers_complete: bool,
    content_length: Option<usize>,
    is_chunked: bool,
}

impl HttpResponseState {
    fn new() -> Self {
        HttpResponseState {
            version: None,
            status_code: None,
            status_text: None,
            headers: HashMap::new(),
            body: Vec::new(),
            raw: Vec::new(),
            headers_complete: false,
            content_length: None,
            is_chunked: false,
        }
    }
}

#[derive(Debug, Clone)]
struct BidirectionalStream {
    client_to_server: TcpStreamBuffer,
    server_to_client: TcpStreamBuffer,
    requests: Vec<HttpRequestState>,
    responses: Vec<HttpResponseState>,
    current_request: Option<HttpRequestState>,
    current_response: Option<HttpResponseState>,
}

impl BidirectionalStream {
    fn new() -> Self {
        BidirectionalStream {
            client_to_server: TcpStreamBuffer::new(),
            server_to_client: TcpStreamBuffer::new(),
            requests: Vec::new(),
            responses: Vec::new(),
            current_request: None,
            current_response: None,
        }
    }
}

pub fn reconstruct_http_sessions(packets: &[PacketInfo]) -> Vec<HTTPSession> {
    let mut streams: HashMap<String, BidirectionalStream> = HashMap::new();
    let mut stream_key_map: HashMap<String, (StreamKey, bool)> = HashMap::new();

    for packet in packets {
        if packet.protocol != "TCP" || packet.payload.is_empty() {
            continue;
        }

        let key = StreamKey {
            src_ip: packet.source_ip.clone(),
            src_port: packet.source_port,
            dst_ip: packet.dest_ip.clone(),
            dst_port: packet.dest_port,
        };

        let (normalized_key, is_reversed) = key.normalize();
        let stream_key = format!(
            "{}:{}<->{}:{}",
            normalized_key.src_ip, normalized_key.src_port,
            normalized_key.dst_ip, normalized_key.dst_port
        );

        stream_key_map.entry(stream_key.clone())
            .or_insert_with(|| (normalized_key, is_reversed));

        let stream = streams.entry(stream_key).or_insert_with(BidirectionalStream::new);

        if !is_reversed {
            process_client_data(stream, &packet.payload);
        } else {
            process_server_data(stream, &packet.payload);
        }
    }

    let mut sessions = Vec::new();

    for (stream_key, stream) in streams {
        let (key_info, _) = &stream_key_map[&stream_key];
        
        if stream.requests.is_empty() && stream.responses.is_empty() {
            continue;
        }

        for (i, request) in stream.requests.iter().enumerate() {
            let response = stream.responses.get(i);
            
            let session = HTTPSession {
                session_id: format!("{}_{}", stream_key, i),
                source_ip: key_info.src_ip.clone(),
                dest_ip: key_info.dst_ip.clone(),
                source_port: key_info.src_port,
                dest_port: key_info.dst_port,
                request: build_http_request(request),
                response: response.and_then(build_http_response),
                packets_count: packets.len(),
                start_time: None,
                end_time: None,
            };
            
            if session.request.is_some() || session.response.is_some() {
                sessions.push(session);
            }
        }
    }

    sessions
}

fn process_client_data(stream: &mut BidirectionalStream, payload: &[u8]) {
    stream.client_to_server.raw.extend_from_slice(payload);
    
    let raw_data = &stream.client_to_server.raw;
    
    if stream.current_request.is_none() {
        if looks_like_http_request(raw_data) {
            stream.current_request = Some(HttpRequestState::new());
        } else {
            return;
        }
    }
    
    if let Some(ref mut request) = stream.current_request {
        request.raw.extend_from_slice(payload);
        
        if !request.headers_complete {
            if let Some(headers_end) = find_double_crlf(&request.raw) {
                parse_request_headers(request, &request.raw[..headers_end]);
                request.headers_complete = true;
                
                if headers_end < request.raw.len() {
                    request.body.extend_from_slice(&request.raw[headers_end..]);
                }
            }
        } else {
            request.body.extend_from_slice(payload);
        }
        
        if is_request_complete(request) {
            stream.requests.push(request.clone());
            stream.current_request = None;
            stream.client_to_server.raw.clear();
        }
    }
}

fn process_server_data(stream: &mut BidirectionalStream, payload: &[u8]) {
    stream.server_to_client.raw.extend_from_slice(payload);
    
    let raw_data = &stream.server_to_client.raw;
    
    if stream.current_response.is_none() {
        if looks_like_http_response(raw_data) {
            stream.current_response = Some(HttpResponseState::new());
        } else {
            return;
        }
    }
    
    if let Some(ref mut response) = stream.current_response {
        response.raw.extend_from_slice(payload);
        
        if !response.headers_complete {
            if let Some(headers_end) = find_double_crlf(&response.raw) {
                parse_response_headers(response, &response.raw[..headers_end]);
                response.headers_complete = true;
                
                if headers_end < response.raw.len() {
                    response.body.extend_from_slice(&response.raw[headers_end..]);
                }
            }
        } else {
            response.body.extend_from_slice(payload);
        }
        
        if is_response_complete(response) {
            stream.responses.push(response.clone());
            stream.current_response = None;
            stream.server_to_client.raw.clear();
        }
    }
}

fn looks_like_http_request(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    
    let methods = [
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", 
        b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "
    ];
    
    for method in methods {
        if data.len() >= method.len() {
            if &data[..method.len()] == method {
                return true;
            }
        }
    }
    
    false
}

fn looks_like_http_response(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    
    if &data[..4] == b"HTTP" {
        return true;
    }
    
    false
}

fn find_double_crlf(data: &[u8]) -> Option<usize> {
    let patterns = [
        b"\r\n\r\n",
        b"\n\n",
        b"\r\r",
    ];
    
    for pattern in &patterns {
        if let Some(pos) = find_subsequence(data, pattern) {
            return Some(pos + pattern.len());
        }
    }
    
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    
    None
}

fn parse_request_headers(request: &mut HttpRequestState, header_data: &[u8]) {
    let text = match String::from_utf8_lossy(header_data) {
        std::borrow::Cow::Borrowed(t) => t.to_string(),
        std::borrow::Cow::Owned(t) => t,
    };
    
    let mut lines = text.lines();
    
    if let Some(first_line) = lines.next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            request.method = Some(parts[0].to_string());
            request.uri = Some(parts[1].to_string());
            if parts.len() >= 3 {
                request.version = Some(parts[2].to_string());
            }
        }
    }
    
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            
            let key_lower = key.to_lowercase();
            if key_lower == "content-length" {
                if let Ok(cl) = value.parse::<usize>() {
                    request.content_length = Some(cl);
                }
            }
            if key_lower == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                request.is_chunked = true;
            }
            
            request.headers.insert(key, value);
        }
    }
}

fn parse_response_headers(response: &mut HttpResponseState, header_data: &[u8]) {
    let text = match String::from_utf8_lossy(header_data) {
        std::borrow::Cow::Borrowed(t) => t.to_string(),
        std::borrow::Cow::Owned(t) => t,
    };
    
    let mut lines = text.lines();
    
    if let Some(first_line) = lines.next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            response.version = Some(parts[0].to_string());
            if let Ok(sc) = parts[1].parse::<u16>() {
                response.status_code = Some(sc);
            }
            if parts.len() > 2 {
                response.status_text = Some(parts[2..].join(" "));
            }
        }
    }
    
    for line in lines {
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            
            let key_lower = key.to_lowercase();
            if key_lower == "content-length" {
                if let Ok(cl) = value.parse::<usize>() {
                    response.content_length = Some(cl);
                }
            }
            if key_lower == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                response.is_chunked = true;
            }
            
            response.headers.insert(key, value);
        }
    }
}

fn is_request_complete(request: &HttpRequestState) -> bool {
    if !request.headers_complete {
        return false;
    }
    
    if request.method.as_ref().map_or(false, |m| m == "GET" || m == "HEAD" || m == "DELETE") {
        return true;
    }
    
    if let Some(cl) = request.content_length {
        return request.body.len() >= cl;
    }
    
    if request.is_chunked {
        return is_chunked_body_complete(&request.body);
    }
    
    !request.body.is_empty()
}

fn is_response_complete(response: &HttpResponseState) -> bool {
    if !response.headers_complete {
        return false;
    }
    
    if let Some(cl) = response.content_length {
        return response.body.len() >= cl;
    }
    
    if response.is_chunked {
        return is_chunked_body_complete(&response.body);
    }
    
    !response.body.is_empty()
}

fn is_chunked_body_complete(body: &[u8]) -> bool {
    if body.len() < 5 {
        return false;
    }
    
    if let Some(pos) = find_subsequence(body, b"0\r\n\r\n") {
        return true;
    }
    
    if let Some(pos) = find_subsequence(body, b"0\n\n") {
        return true;
    }
    
    false
}

fn build_http_request(state: &HttpRequestState) -> Option<HTTPRequest> {
    if state.method.is_none() || state.uri.is_none() {
        return None;
    }
    
    let body_str = String::from_utf8_lossy(&state.body).to_string();
    let raw_str = String::from_utf8_lossy(&state.raw).to_string();
    
    Some(HTTPRequest {
        method: state.method.clone().unwrap_or_default(),
        uri: state.uri.clone().unwrap_or_default(),
        version: state.version.clone().unwrap_or_else(|| "HTTP/1.1".to_string()),
        headers: state.headers.clone(),
        body: body_str,
        raw: raw_str,
    })
}

fn build_http_response(state: &HttpResponseState) -> Option<HTTPResponse> {
    if state.status_code.is_none() {
        return None;
    }
    
    let body_str = String::from_utf8_lossy(&state.body).to_string();
    let raw_str = String::from_utf8_lossy(&state.raw).to_string();
    
    Some(HTTPResponse {
        version: state.version.clone().unwrap_or_else(|| "HTTP/1.1".to_string()),
        status_code: state.status_code.unwrap_or(0),
        status_text: state.status_text.clone().unwrap_or_default(),
        headers: state.headers.clone(),
        body: body_str,
        raw: raw_str,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stream_key_normalization() {
        let key1 = StreamKey {
            src_ip: "192.168.1.1".to_string(),
            src_port: 1234,
            dst_ip: "10.0.0.1".to_string(),
            dst_port: 80,
        };
        
        let key2 = StreamKey {
            src_ip: "10.0.0.1".to_string(),
            src_port: 80,
            dst_ip: "192.168.1.1".to_string(),
            dst_port: 1234,
        };
        
        let (norm1, _) = key1.normalize();
        let (norm2, _) = key2.normalize();
        
        assert_eq!(norm1.src_ip, norm2.src_ip);
        assert_eq!(norm1.src_port, norm2.src_port);
    }
    
    #[test]
    fn test_looks_like_http_request() {
        assert!(looks_like_http_request(b"GET /index.html HTTP/1.1\r\n"));
        assert!(looks_like_http_request(b"POST /api/login HTTP/1.1\r\n"));
        assert!(!looks_like_http_request(b"HTTP/1.1 200 OK\r\n"));
        assert!(!looks_like_http_request(b"random data"));
    }
    
    #[test]
    fn test_looks_like_http_response() {
        assert!(looks_like_http_response(b"HTTP/1.1 200 OK\r\n"));
        assert!(looks_like_http_response(b"HTTP/1.0 404 Not Found\r\n"));
        assert!(!looks_like_http_response(b"GET / HTTP/1.1\r\n"));
    }
    
    #[test]
    fn test_find_double_crlf() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody content";
        let pos = find_double_crlf(data);
        assert!(pos.is_some());
        
        let data2 = b"GET / HTTP/1.1\nHost: example.com\n\nbody content";
        let pos2 = find_double_crlf(data2);
        assert!(pos2.is_some());
    }
    
    #[test]
    fn test_tcp_stream_reassembly() {
        let mut buffer = TcpStreamBuffer::new();
        
        buffer.add_segment(1000, b"Hello ");
        buffer.add_segment(1006, b"World");
        
        let reassembled = buffer.reassemble();
        assert_eq!(reassembled, b"Hello World");
    }
    
    #[test]
    fn test_out_of_order_reassembly() {
        let mut buffer = TcpStreamBuffer::new();
        
        buffer.add_segment(1006, b"World");
        buffer.add_segment(1000, b"Hello ");
        
        let reassembled = buffer.reassemble();
        assert_eq!(reassembled, b"Hello World");
    }
}
