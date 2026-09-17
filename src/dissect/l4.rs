//! Transport-layer dissectors: TCP, UDP; dispatch to L7.

use crate::dissect::decrypt::KeyLog;
use crate::dissect::dhcp::dissect_dhcp;
use crate::dissect::dns::dissect_dns;
use crate::dissect::http1::dissect_http1;
use crate::dissect::http2::dissect_http2;
use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::quic::{dissect_quic, looks_like_quic_initial, looks_like_quic_short};
use crate::dissect::tls_dissect::dissect_tls;
use crate::dissect::tree::ProtoTree;
use crate::dissect::voip::{dissect_rtp, dissect_sip, looks_like_rtp, looks_like_sip};
use crate::dissect::websocket::dissect_websocket;

thread_local! {
    static ACTIVE_KEYLOG: std::cell::Cell<Option<&'static KeyLog>> = const { std::cell::Cell::new(None) };
}

/// Set keylog for the duration of a top-level `dissect()` call (UDP QUIC 1-RTT).
pub fn with_keylog<R>(keylog: Option<&KeyLog>, f: impl FnOnce() -> R) -> R {
    // SAFETY: keylog lives for the duration of f; we clear before return.
    ACTIVE_KEYLOG.with(|c| {
        let prev = c.replace(unsafe {
            std::mem::transmute::<Option<&KeyLog>, Option<&'static KeyLog>>(keylog)
        });
        let r = f();
        c.set(prev);
        r
    })
}

fn active_keylog() -> Option<&'static KeyLog> {
    ACTIVE_KEYLOG.with(|c| c.get())
}

pub fn dissect_tcp<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    if data.len() < 20 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    flags.tcp = true;
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_off = ((data[12] >> 4) as usize) * 4;
    let fl = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);

    let sec = tree.add_section(
        parent,
        "Transmission Control Protocol",
        offset,
        data_off.min(data.len()),
    );
    tree.add_child(sec, "Source Port", format!("{sport}"), offset, 2);
    tree.add_child(sec, "Destination Port", format!("{dport}"), offset + 2, 2);
    tree.add_child(sec, "Sequence Number", format!("{seq}"), offset + 4, 4);
    tree.add_child(
        sec,
        "Acknowledgment Number",
        format!("{ack}"),
        offset + 8,
        4,
    );
    tree.add_child(sec, "Flags", format_tcp_flags(fl), offset + 13, 1);
    tree.add_child(sec, "Window", format!("{window}"), offset + 14, 2);

    let hdr = data_off.min(data.len());
    if data_off > 20 && data.len() >= data_off {
        tree.add_child(
            sec,
            "Options",
            format!("{} bytes", data_off - 20),
            offset + 20,
            data_off - 20,
        );
    }

    let payload = if data.len() > hdr { &data[hdr..] } else { &[] };
    let payload_off = offset + hdr;

    // Update addresses with ports
    if !summary.src.is_empty() {
        summary.src = format!("{}:{}", summary.src, sport);
    }
    if !summary.dst.is_empty() {
        summary.dst = format!("{}:{}", summary.dst, dport);
    }

    summary.protocol = "TCP".into();
    summary.info = format!(
        "{} → {} [{}] Seq={} Ack={} Win={} Len={}",
        sport,
        dport,
        format_tcp_flags(fl),
        seq,
        ack,
        window,
        payload.len()
    );

    if payload.is_empty() {
        return LayerResult {
            payload,
            payload_offset: payload_off,
        };
    }

    // L7 heuristics by port / content
    if sport == 443 || dport == 443 || looks_like_tls(payload) {
        return dissect_tls(tree, parent, payload, payload_off, flags, summary);
    }
    if payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") || looks_like_http2(payload) {
        return dissect_http2(tree, parent, payload, payload_off, flags, summary);
    }
    if looks_like_http1(payload) {
        let r = dissect_http1(tree, parent, payload, payload_off, flags, summary);
        // Check Upgrade: websocket
        if payload
            .windows(9)
            .any(|w| w.eq_ignore_ascii_case(b"websocket"))
        {
            flags.websocket = true;
        }
        return r;
    }
    if flags.websocket || looks_like_ws_frame(payload) {
        return dissect_websocket(tree, parent, payload, payload_off, flags, summary);
    }
    if sport == 5060 || dport == 5060 || looks_like_sip(payload) {
        dissect_sip(tree, parent, payload, flags, summary);
        return LayerResult {
            payload,
            payload_offset: payload_off,
        };
    }

    LayerResult {
        payload,
        payload_offset: payload_off,
    }
}

pub fn dissect_udp<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    if data.len() < 8 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    flags.udp = true;
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let len = u16::from_be_bytes([data[4], data[5]]) as usize;

    let sec = tree.add_section(parent, "User Datagram Protocol", offset, 8);
    tree.add_child(sec, "Source Port", format!("{sport}"), offset, 2);
    tree.add_child(sec, "Destination Port", format!("{dport}"), offset + 2, 2);
    tree.add_child(sec, "Length", format!("{len}"), offset + 4, 2);

    if !summary.src.is_empty() {
        summary.src = format!("{}:{}", summary.src, sport);
    }
    if !summary.dst.is_empty() {
        summary.dst = format!("{}:{}", summary.dst, dport);
    }

    let payload = &data[8..];
    let payload_off = offset + 8;
    summary.protocol = "UDP".into();
    summary.info = format!("{} → {} Len={}", sport, dport, payload.len());

    // DNS / mDNS / LLMNR
    if sport == 53
        || dport == 53
        || sport == 5353
        || dport == 5353
        || sport == 5355
        || dport == 5355
    {
        let r = dissect_dns(tree, parent, payload, payload_off, flags, summary);
        if sport == 5353 || dport == 5353 {
            flags.mdns = true;
            flags.dns = true;
            summary.protocol = "MDNS".into();
        } else if sport == 5355 || dport == 5355 {
            flags.llmnr = true;
            flags.dns = true;
            summary.protocol = "LLMNR".into();
        }
        return r;
    }
    // DHCP
    if sport == 67 || dport == 67 || sport == 68 || dport == 68 {
        return dissect_dhcp(tree, parent, payload, payload_off, flags, summary);
    }
    // SIP / RTP (VoIP)
    if sport == 5060 || dport == 5060 || looks_like_sip(payload) {
        dissect_sip(tree, parent, payload, flags, summary);
        return LayerResult {
            payload,
            payload_offset: payload_off,
        };
    }
    if looks_like_rtp(payload) {
        dissect_rtp(tree, parent, payload, flags, summary);
        return LayerResult {
            payload,
            payload_offset: payload_off,
        };
    }
    // QUIC
    if looks_like_quic_initial(payload)
        || (looks_like_quic_short(payload) && payload.len() > 20)
        || ((sport == 443 || dport == 443) && !payload.is_empty() && (payload[0] & 0x80) != 0)
    {
        dissect_quic(
            tree,
            parent,
            payload,
            payload_off,
            flags,
            summary,
            active_keylog(),
        );
        if summary.info.is_empty() || summary.info.starts_with("Len=") {
            summary.info = format!("{} → {} {}", sport, dport, summary.protocol);
        }
    }

    LayerResult {
        payload,
        payload_offset: payload_off,
    }
}

fn format_tcp_flags(f: u8) -> String {
    let mut parts = Vec::new();
    if f & 0x01 != 0 {
        parts.push("FIN");
    }
    if f & 0x02 != 0 {
        parts.push("SYN");
    }
    if f & 0x04 != 0 {
        parts.push("RST");
    }
    if f & 0x08 != 0 {
        parts.push("PSH");
    }
    if f & 0x10 != 0 {
        parts.push("ACK");
    }
    if f & 0x20 != 0 {
        parts.push("URG");
    }
    if parts.is_empty() {
        format!("{f:#04x}")
    } else {
        parts.join(",")
    }
}

fn looks_like_tls(p: &[u8]) -> bool {
    p.len() >= 5 && (p[0] == 0x16 || p[0] == 0x17 || p[0] == 0x15 || p[0] == 0x14) && p[1] == 0x03
}

fn looks_like_http1(p: &[u8]) -> bool {
    let s = std::str::from_utf8(&p[..p.len().min(16)]).unwrap_or("");
    s.starts_with("GET ")
        || s.starts_with("POST ")
        || s.starts_with("PUT ")
        || s.starts_with("HEAD ")
        || s.starts_with("DELETE ")
        || s.starts_with("OPTIONS ")
        || s.starts_with("PATCH ")
        || s.starts_with("HTTP/1.")
}

fn looks_like_http2(p: &[u8]) -> bool {
    // Frame: length(24) type(8) flags(8) stream(31)
    if p.len() < 9 {
        return false;
    }
    let len = ((p[0] as usize) << 16) | ((p[1] as usize) << 8) | p[2] as usize;
    let typ = p[3];
    typ <= 0x09 && len + 9 <= p.len() + 16384
}

fn looks_like_ws_frame(p: &[u8]) -> bool {
    if p.len() < 2 {
        return false;
    }
    let opcode = p[0] & 0x0f;
    matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xa) && (p[0] & 0x70) == 0
}
