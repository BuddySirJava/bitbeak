//! Stream follow and HTTP object export.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::dissect::packet::PacketRecord;

#[derive(Debug, Clone)]
pub struct FollowResult {
    pub label: String,
    pub text: String,
    pub raw: Bytes,
    pub objects: Vec<HttpObject>,
}

#[derive(Debug, Clone)]
pub struct HttpObject {
    pub name: String,
    pub content_type: String,
    pub data: Bytes,
}

/// Follow TCP stream containing `selected` (4-tuple match, bidirectional).
pub fn follow_tcp(packets: &[&PacketRecord], selected: &PacketRecord) -> FollowResult {
    let sel_src = selected.summary.src.clone();
    let sel_dst = selected.summary.dst.clone();
    let mut segments: Vec<(u32, bool, Bytes)> = Vec::new();

    for p in packets {
        if !p.flags.tcp {
            continue;
        }
        let same = (p.summary.src == sel_src && p.summary.dst == sel_dst)
            || (p.summary.src == sel_dst && p.summary.dst == sel_src);
        if !same {
            continue;
        }
        let forward = p.summary.src == sel_src;
        if let Some((seq, payload)) = tcp_payload(p) {
            if !payload.is_empty() {
                segments.push((seq, forward, payload));
            }
        }
    }

    // Reassemble per direction by seq
    let mut forward_map = BTreeMap::new();
    let mut reverse_map = BTreeMap::new();
    for (seq, forward, payload) in segments {
        if forward {
            forward_map.insert(seq, payload);
        } else {
            reverse_map.insert(seq, payload);
        }
    }

    let mut raw = Vec::new();
    let mut text = String::new();
    text.push_str("--- Client → Server ---\n");
    for p in forward_map.values() {
        raw.extend_from_slice(p);
        text.push_str(&lossy_utf8(p));
    }
    text.push_str("\n--- Server → Client ---\n");
    for p in reverse_map.values() {
        raw.extend_from_slice(p);
        text.push_str(&lossy_utf8(p));
    }

    FollowResult {
        label: format!("TCP {} ↔ {}", sel_src, sel_dst),
        text,
        raw: Bytes::from(raw),
        objects: Vec::new(),
    }
}

pub fn follow_udp(packets: &[&PacketRecord], selected: &PacketRecord) -> FollowResult {
    let sel_src = &selected.summary.src;
    let sel_dst = &selected.summary.dst;
    let mut raw = Vec::new();
    let mut text = String::new();
    for p in packets {
        if !p.flags.udp {
            continue;
        }
        let same = (p.summary.src == *sel_src && p.summary.dst == *sel_dst)
            || (p.summary.src == *sel_dst && p.summary.dst == *sel_src);
        if !same {
            continue;
        }
        if let Some(payload) = udp_payload(p) {
            text.push_str(&format!(
                "[{} → {}] {}\n",
                p.summary.src,
                p.summary.dst,
                lossy_utf8(&payload)
            ));
            raw.extend_from_slice(&payload);
        }
    }
    FollowResult {
        label: format!("UDP {} ↔ {}", sel_src, sel_dst),
        text,
        raw: Bytes::from(raw),
        objects: Vec::new(),
    }
}

pub fn follow_http(packets: &[&PacketRecord], selected: &PacketRecord) -> FollowResult {
    let mut base = follow_tcp(packets, selected);
    base.label = format!("HTTP {}", base.label);
    base.objects = extract_http_objects(&base.raw);
    // Prefer decoded text view
    if !base.objects.is_empty() {
        let mut t = base.text.clone();
        t.push_str("\n--- Objects ---\n");
        for o in &base.objects {
            t.push_str(&format!(
                "{} ({}, {} bytes)\n",
                o.name,
                o.content_type,
                o.data.len()
            ));
        }
        base.text = t;
    }
    base
}

pub fn extract_http_objects(raw: &[u8]) -> Vec<HttpObject> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(raw);
    // Split on HTTP message starts
    for (i, chunk) in text.split("HTTP/1.").enumerate() {
        if i == 0 && !chunk.contains("HTTP/") {
            // May start with request
            if let Some(obj) = parse_http_message(chunk) {
                out.push(obj);
            }
            continue;
        }
        let msg = format!("HTTP/1.{chunk}");
        if let Some(obj) = parse_http_message(&msg) {
            out.push(obj);
        }
    }
    // Also try request at start
    if out.is_empty() {
        if let Some(obj) = parse_http_message(&text) {
            out.push(obj);
        }
    }
    out
}

fn parse_http_message(msg: &str) -> Option<HttpObject> {
    let (head, body) = msg.split_once("\r\n\r\n")?;
    let first = head.lines().next()?;
    let name = first.chars().take(60).collect::<String>();
    let mut content_type = "application/octet-stream".to_string();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-type") {
                content_type = v.trim().to_string();
            }
        }
    }
    if body.is_empty() {
        return None;
    }
    Some(HttpObject {
        name,
        content_type,
        data: Bytes::copy_from_slice(body.as_bytes()),
    })
}

fn tcp_payload(p: &PacketRecord) -> Option<(u32, Bytes)> {
    let data = &p.data[..];
    let ip_off = ipv4_payload_offset(data)?;
    if data.len() < ip_off + 20 {
        return None;
    }
    let ihl = (data[ip_off] & 0x0f) as usize * 4;
    let tcp_off = ip_off + ihl;
    if data.len() < tcp_off + 20 {
        return None;
    }
    let seq = u32::from_be_bytes([
        data[tcp_off + 4],
        data[tcp_off + 5],
        data[tcp_off + 6],
        data[tcp_off + 7],
    ]);
    let doff = ((data[tcp_off + 12] >> 4) as usize) * 4;
    let payload_off = tcp_off + doff;
    if payload_off > data.len() {
        return None;
    }
    Some((seq, Bytes::copy_from_slice(&data[payload_off..])))
}

fn udp_payload(p: &PacketRecord) -> Option<Bytes> {
    let data = &p.data[..];
    let ip_off = ipv4_payload_offset(data)?;
    if data.len() < ip_off + 20 {
        return None;
    }
    let ihl = (data[ip_off] & 0x0f) as usize * 4;
    let udp_off = ip_off + ihl;
    if data.len() < udp_off + 8 {
        return None;
    }
    Some(Bytes::copy_from_slice(&data[udp_off + 8..]))
}

fn ipv4_payload_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 14 {
        return None;
    }
    // Assume Ethernet for follow helpers
    let mut off = 14;
    let mut et = u16::from_be_bytes([data[12], data[13]]);
    if et == 0x8100 && data.len() >= 18 {
        et = u16::from_be_bytes([data[16], data[17]]);
        off = 18;
    }
    if et == 0x0800 {
        Some(off)
    } else {
        None
    }
}

fn lossy_utf8(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::packet::{LinkType, PacketSummary, ProtocolFlags};
    use std::time::{Instant, SystemTime};

    fn fake_tcp(id: u64, src: &str, dst: &str, seq: u32, payload: &[u8]) -> PacketRecord {
        // Build minimal eth+ipv4+tcp+payload
        let mut data = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        let tcp_len = 20 + payload.len();
        let total = (20 + tcp_len) as u16;
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        ip[2] = (total >> 8) as u8;
        ip[3] = (total & 0xff) as u8;
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[12] = 0x50; // data off 5
        tcp[13] = 0x18; // PSH ACK
        data.extend_from_slice(&ip);
        data.extend_from_slice(&tcp);
        data.extend_from_slice(payload);

        PacketRecord {
            id,
            at: Instant::now(),
            wall: SystemTime::now(),
            interface: "test".into(),
            link_type: LinkType::Ethernet,
            orig_len: data.len() as u32,
            data: Bytes::from(data),
            summary: PacketSummary {
                src: src.into(),
                dst: dst.into(),
                protocol: "TCP".into(),
                info: String::new(),
                len: 0,
            },
            flags: ProtocolFlags {
                tcp: true,
                ipv4: true,
                ethernet: true,
                ..Default::default()
            },
            expert: Vec::new(),
            tree: None,
            decrypted: None,
            fields: Default::default(),
        }
    }

    #[test]
    fn reassembles_out_of_order_tcp() {
        let a = fake_tcp(1, "10.0.0.1:12345", "10.0.0.2:80", 100, b"Hello ");
        let b = fake_tcp(2, "10.0.0.1:12345", "10.0.0.2:80", 106, b"World");
        // Deliver out of order
        let packets = [&b, &a];
        let r = follow_tcp(&packets, &a);
        assert!(r.text.contains("Hello World") || r.raw.windows(11).any(|w| w == b"Hello World"));
        // raw should be in seq order
        assert_eq!(&r.raw[..], b"Hello World");
    }
}
