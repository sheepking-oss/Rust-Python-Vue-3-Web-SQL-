use super::PacketInfo;
use chrono::NaiveDateTime;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn parse_pcap_file<P: AsRef<Path>>(file_path: P) -> Result<Vec<PacketInfo>, String> {
    let mut file = File::open(file_path).map_err(|e| format!("无法打开文件: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| format!("读取文件失败: {}", e))?;

    let mut packets = Vec::new();
    let mut offset = 0;

    if buffer.len() < 24 {
        return Err("PCAP 文件头太短".to_string());
    }

    let magic_number = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let is_nanosecond = magic_number == 0xa1b2c3d4 || magic_number == 0xd4c3b2a1;
    
    offset = 24;

    while offset + 16 <= buffer.len() {
        let ts_sec = u32::from_le_bytes([buffer[offset], buffer[offset+1], buffer[offset+2], buffer[offset+3]]);
        let ts_usec = u32::from_le_bytes([buffer[offset+4], buffer[offset+5], buffer[offset+6], buffer[offset+7]]);
        let incl_len = u32::from_le_bytes([buffer[offset+8], buffer[offset+9], buffer[offset+10], buffer[offset+11]]) as usize;
        let orig_len = u32::from_le_bytes([buffer[offset+12], buffer[offset+13], buffer[offset+14], buffer[offset+15]]) as usize;

        offset += 16;

        if offset + incl_len > buffer.len() {
            break;
        }

        let packet_data = &buffer[offset..offset + incl_len];
        
        if let Some(packet_info) = parse_packet_data(packet_data, ts_sec, ts_usec, is_nanosecond) {
            packets.push(packet_info);
        }

        offset += incl_len;
    }

    Ok(packets)
}

fn parse_packet_data(
    data: &[u8],
    ts_sec: u32,
    ts_usec: u32,
    is_nanosecond: bool,
) -> Option<PacketInfo> {
    let timestamp = if is_nanosecond {
        let nanos = ts_sec as i64 * 1_000_000_000 + ts_usec as i64;
        NaiveDateTime::from_timestamp_opt(nanos / 1_000_000_000, (nanos % 1_000_000_000) as u32)
    } else {
        let micros = ts_sec as i64 * 1_000_000 + ts_usec as i64;
        NaiveDateTime::from_timestamp_opt(micros / 1_000_000, ((micros % 1_000_000) * 1_000) as u32)
    };

    if let Some(ethernet) = EthernetPacket::new(data) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    return parse_ipv4_packet(&ipv4, timestamp, data.len());
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    return parse_ipv6_packet(&ipv6, timestamp, data.len());
                }
            }
            _ => {}
        }
    }

    None
}

fn parse_ipv4_packet(ipv4: &Ipv4Packet, timestamp: Option<NaiveDateTime>, packet_length: usize) -> Option<PacketInfo> {
    let source_ip = ipv4.get_source().to_string();
    let dest_ip = ipv4.get_destination().to_string();

    match ipv4.get_next_level_protocol() {
        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                return Some(PacketInfo {
                    timestamp,
                    source_ip,
                    dest_ip,
                    source_port: tcp.get_source(),
                    dest_port: tcp.get_destination(),
                    protocol: "TCP".to_string(),
                    payload: tcp.payload().to_vec(),
                    packet_length,
                });
            }
        }
        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                return Some(PacketInfo {
                    timestamp,
                    source_ip,
                    dest_ip,
                    source_port: udp.get_source(),
                    dest_port: udp.get_destination(),
                    protocol: "UDP".to_string(),
                    payload: udp.payload().to_vec(),
                    packet_length,
                });
            }
        }
        _ => {}
    }

    None
}

fn parse_ipv6_packet(ipv6: &Ipv6Packet, timestamp: Option<NaiveDateTime>, packet_length: usize) -> Option<PacketInfo> {
    let source_ip = ipv6.get_source().to_string();
    let dest_ip = ipv6.get_destination().to_string();

    match ipv6.get_next_header() {
        pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                return Some(PacketInfo {
                    timestamp,
                    source_ip,
                    dest_ip,
                    source_port: tcp.get_source(),
                    dest_port: tcp.get_destination(),
                    protocol: "TCP".to_string(),
                    payload: tcp.payload().to_vec(),
                    packet_length,
                });
            }
        }
        pnet::packet::ip::IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                return Some(PacketInfo {
                    timestamp,
                    source_ip,
                    dest_ip,
                    source_port: udp.get_source(),
                    dest_port: udp.get_destination(),
                    protocol: "UDP".to_string(),
                    payload: udp.payload().to_vec(),
                    packet_length,
                });
            }
        }
        _ => {}
    }

    None
}
