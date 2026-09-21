//! Stream follow and HTTP object export.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::dissect::packet::{LinkType, PacketRecord};

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
    /// True when the message is an HTTP request (not a response).
    pub is_request: bool,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
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
    let (head, body) = msg
        .split_once("\r\n\r\n")
        .or_else(|| msg.split_once("\n\n"))?;
    let first = head.lines().next()?.trim();
    if first.is_empty() {
        return None;
    }
    let name = first.chars().take(60).collect::<String>();
    let mut content_type = "application/octet-stream".to_string();
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-type") {
                content_type = val.clone();
            }
            headers.push((key, val));
        }
    }
    let is_request = !first.starts_with("HTTP/");
    let (method, url) = if is_request {
        let mut parts = first.split_whitespace();
        let m = parts.next().unwrap_or("GET").to_string();
        let path = parts.next().unwrap_or("/").to_string();
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path
        } else if !host.is_empty() {
            format!("http://{host}{path}")
        } else {
            path
        };
        (m, url)
    } else {
        (String::new(), String::new())
    };
    // Keep request objects even with empty body (GET).
    if !is_request && body.is_empty() {
        return None;
    }
    Some(HttpObject {
        name,
        content_type,
        data: Bytes::copy_from_slice(body.as_bytes()),
        is_request,
        method,
        url,
        headers,
    })
}

/// Build a bpf/tcpdump-style capture filter from an HTTP(S) URL.
pub fn capture_filter_for_url(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let is_https = url.starts_with("https://");
    let hostport = rest.split('/').next()?.split('?').next()?;
    let (host, port_opt) = if let Some(inner) = hostport.strip_prefix('[') {
        let end = inner.find(']')?;
        let host = inner[..end].to_string();
        let port = inner[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok());
        (host, port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        if p.chars().all(|c| c.is_ascii_digit()) {
            (h.to_string(), p.parse().ok())
        } else {
            (hostport.to_string(), None)
        }
    } else {
        (hostport.to_string(), None)
    };
    if host.is_empty() {
        return None;
    }
    let default_port = if is_https { 443 } else { 80 };
    let port = port_opt.unwrap_or(default_port);
    if port == default_port {
        Some(format!("host {host}"))
    } else {
        Some(format!("host {host} and port {port}"))
    }
}

fn tcp_payload(p: &PacketRecord) -> Option<(u32, Bytes)> {
    let data = &p.data[..];
    if let Some((seq, wire)) = tcp_payload_from_wire(data, p.link_type) {
        if let Some(dec) = &p.decrypted {
            return Some((seq, dec.clone()));
        }
        return Some((seq, wire));
    }
    // No L4 header (or non-IP) but decryptor filled application bytes.
    p.decrypted.as_ref().map(|dec| (0u32, dec.clone()))
}

fn tcp_payload_from_wire(data: &[u8], link: LinkType) -> Option<(u32, Bytes)> {
    let (ip_off, is_v6) = ip_payload_offset(data, link)?;
    if is_v6 {
        if data.len() < ip_off + 40 {
            return None;
        }
        let mut next = data[ip_off + 6];
        let mut hdr_off = ip_off + 40;
        while matches!(next, 0 | 43 | 44 | 51 | 60) {
            if data.len() < hdr_off + 2 {
                return None;
            }
            next = data[hdr_off];
            let hdr_len = (data[hdr_off + 1] as usize + 1) * 8;
            hdr_off += hdr_len;
        }
        if next != 6 {
            return None;
        }
        let tcp_off = hdr_off;
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
        return Some((seq, Bytes::copy_from_slice(&data[payload_off..])));
    }
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
    if let Some(wire) = udp_payload_from_wire(data, p.link_type) {
        if let Some(dec) = &p.decrypted {
            return Some(dec.clone());
        }
        return Some(wire);
    }
    p.decrypted.clone()
}

fn udp_payload_from_wire(data: &[u8], link: LinkType) -> Option<Bytes> {
    let (ip_off, is_v6) = ip_payload_offset(data, link)?;
    if is_v6 {
        if data.len() < ip_off + 40 {
            return None;
        }
        let mut next = data[ip_off + 6];
        let mut hdr_off = ip_off + 40;
        while matches!(next, 0 | 43 | 44 | 51 | 60) {
            if data.len() < hdr_off + 2 {
                return None;
            }
            next = data[hdr_off];
            let hdr_len = (data[hdr_off + 1] as usize + 1) * 8;
            hdr_off += hdr_len;
        }
        if next != 17 {
            return None;
        }
        let udp_off = hdr_off;
        if data.len() < udp_off + 8 {
            return None;
        }
        return Some(Bytes::copy_from_slice(&data[udp_off + 8..]));
    }
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

/// Returns (offset_to_IP_header, is_ipv6).
fn ip_payload_offset(data: &[u8], link: LinkType) -> Option<(usize, bool)> {
    match link {
        LinkType::Ethernet | LinkType::Unknown(_) => {
            if data.len() < 14 {
                return None;
            }
            let mut off = 14;
            let mut et = u16::from_be_bytes([data[12], data[13]]);
            if et == 0x8100 && data.len() >= 18 {
                et = u16::from_be_bytes([data[16], data[17]]);
                off = 18;
            }
            match et {
                0x0800 => Some((off, false)),
                0x86dd => Some((off, true)),
                _ => None,
            }
        }
        LinkType::LinuxSll => {
            if data.len() < 16 {
                return None;
            }
            let et = u16::from_be_bytes([data[14], data[15]]);
            match et {
                0x0800 => Some((16, false)),
                0x86dd => Some((16, true)),
                _ => None,
            }
        }
        LinkType::LinuxSll2 => {
            if data.len() < 20 {
                return None;
            }
            let et = u16::from_be_bytes([data[0], data[1]]);
            match et {
                0x0800 => Some((20, false)),
                0x86dd => Some((20, true)),
                _ => None,
            }
        }
        LinkType::Raw => {
            if data.is_empty() {
                return None;
            }
            match data[0] >> 4 {
                4 => Some((0, false)),
                6 => Some((0, true)),
                _ => None,
            }
        }
        LinkType::Null => {
            // BSD loopback: 4-byte AF family, then IP
            if data.len() < 4 {
                return None;
            }
            let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            // AF_INET=2, AF_INET6=24/28/30 depending on OS — sniff version nibble
            if data.len() > 4 {
                match data[4] >> 4 {
                    4 => Some((4, false)),
                    6 => Some((4, true)),
                    _ if af == 2 => Some((4, false)),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
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

    #[test]
    fn capture_filter_from_url() {
        assert_eq!(
            capture_filter_for_url("https://example.com/path"),
            Some("host example.com".into())
        );
        assert_eq!(
            capture_filter_for_url("http://api.local:8080/v1"),
            Some("host api.local and port 8080".into())
        );
        assert_eq!(
            capture_filter_for_url("https://[2001:db8::1]:8443/"),
            Some("host 2001:db8::1 and port 8443".into())
        );
    }

    #[test]
    fn parse_http_request_object() {
        let msg = "GET /hello HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\n";
        let obj = parse_http_message(msg).unwrap();
        assert!(obj.is_request);
        assert_eq!(obj.method, "GET");
        assert_eq!(obj.url, "http://example.com/hello");
        assert!(obj.data.is_empty());
    }
}
