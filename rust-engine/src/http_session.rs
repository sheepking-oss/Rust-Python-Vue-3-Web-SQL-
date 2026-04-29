use super::{HTTPSession, HTTPRequest, HTTPResponse, PacketInfo};
use std::collections::HashMap;
use std::str;

pub fn reconstruct_http_sessions(packets: &[PacketInfo]) -> Vec<HTTPSession> {
    let mut tcp_streams: HashMap<String, Vec<&PacketInfo>> = HashMap::new();

    for packet in packets {
        if packet.protocol == "TCP" && !packet.payload.is_empty() {
            let stream_key = format!(
                "{}:{}<->{}:{}",
                packet.source_ip, packet.source_port,
                packet.dest_ip, packet.dest_port
            );
            tcp_streams.entry(stream_key).or_default().push(packet);
        }
    }

    let mut sessions = Vec::new();

    for (stream_key, stream_packets) in tcp_streams {
        if let Some(session) = process_tcp_stream(&stream_key, &stream_packets) {
            sessions.push(session);
        }
    }

    sessions
}

fn process_tcp_stream(stream_key: &str, packets: &[&PacketInfo]) -> Option<HTTPSession> {
    if packets.is_empty() {
        return None;
    }

    let first_packet = packets[0];
    let mut request_data = Vec::new();
    let mut response_data = Vec::new();
    let mut is_request = true;

    for packet in packets {
        if !packet.payload.is_empty() {
            let payload = &packet.payload;
            
            if starts_with_http_request(payload) {
                is_request = true;
                request_data.extend_from_slice(payload);
            } else if starts_with_http_response(payload) {
                is_request = false;
                response_data.extend_from_slice(payload);
            } else if is_request {
                request_data.extend_from_slice(payload);
            } else {
                response_data.extend_from_slice(payload);
            }
        }
    }

    let request = if !request_data.is_empty() {
        parse_http_request(&request_data)
    } else {
        None
    };

    let response = if !response_data.is_empty() {
        parse_http_response(&response_data)
    } else {
        None
    };

    if request.is_none() && response.is_none() {
        return None;
    }

    let start_time = packets.first().and_then(|p| p.timestamp);
    let end_time = packets.last().and_then(|p| p.timestamp);

    Some(HTTPSession {
        session_id: stream_key.to_string(),
        source_ip: first_packet.source_ip.clone(),
        dest_ip: first_packet.dest_ip.clone(),
        source_port: first_packet.source_port,
        dest_port: first_packet.dest_port,
        request,
        response,
        packets_count: packets.len(),
        start_time,
        end_time,
    })
}

fn starts_with_http_request(data: &[u8]) -> bool {
    let http_methods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "];
    
    for method in http_methods {
        if data.len() >= method.len() {
            if &data[..method.len()] == method.as_bytes() {
                return true;
            }
        }
    }
    false
}

fn starts_with_http_response(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    
    &data[..4] == b"HTTP"
}

fn parse_http_request(data: &[u8]) -> Option<HTTPRequest> {
    let text = match str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return None,
    };

    let mut lines = text.lines();
    let first_line = lines.next()?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let method = parts[0].to_string();
    let uri = parts[1].to_string();
    let version = parts[2].to_string();

    let mut headers = HashMap::new();
    let mut body = String::new();
    let mut in_body = false;

    for line in lines {
        if in_body {
            body.push_str(line);
            body.push('\n');
        } else if line.is_empty() {
            in_body = true;
        } else if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    Some(HTTPRequest {
        method,
        uri,
        version,
        headers,
        body,
        raw: text.to_string(),
    })
}

fn parse_http_response(data: &[u8]) -> Option<HTTPResponse> {
    let text = match str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return None,
    };

    let mut lines = text.lines();
    let first_line = lines.next()?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let version = parts[0].to_string();
    let status_code: u16 = parts[1].parse().unwrap_or(0);
    let status_text = if parts.len() > 2 {
        parts[2..].join(" ")
    } else {
        String::new()
    };

    let mut headers = HashMap::new();
    let mut body = String::new();
    let mut in_body = false;

    for line in lines {
        if in_body {
            body.push_str(line);
            body.push('\n');
        } else if line.is_empty() {
            in_body = true;
        } else if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    Some(HTTPResponse {
        version,
        status_code,
        status_text,
        headers,
        body,
        raw: text.to_string(),
    })
}
