//! Packet dissection: protocol tree, L2–L7 parsers, follow, expert, names.

pub mod analysis;
pub mod coloring;
pub mod decrypt;
pub mod expert;
pub mod follow;
pub mod geoip;
pub mod names;
pub mod packet;
pub mod reassembly;
pub mod tree;

mod dhcp;
mod dns;
mod http1;
mod http2;
mod l2;
mod l3;
mod l4;
mod quic;
mod tls_dissect;
mod voip;
mod websocket;
mod wifi;

pub use analysis::{
    ConversationKind, ConversationRow, ConversationTable, EndpointKind, EndpointRow, EndpointTable,
    IoBucket, IoGraph, LengthHistogram, ProtoHierarchy,
};
pub use coloring::{color_for_packet, ColorRule};
pub use decrypt::{DecryptState, KeyLog};
pub use expert::{ExpertInfo, ExpertSeverity};
pub use follow::{
    capture_filter_for_url, follow_http, follow_tcp, follow_udp, FollowResult, HttpObject,
};
pub use geoip::GeoDb;
pub use names::NameResolver;
pub use packet::{DisplayFields, LinkType, PacketRecord, PacketStore, PacketSummary};
pub use reassembly::{defrag_ipv4, export_http_objects, Ipv4Defrag};
pub use tree::{ProtoNode, ProtoTree};

use bytes::Bytes;

use crate::dissect::decrypt::{decrypt_tls_in_frame, extract_client_random};
use crate::dissect::expert::collect_expert;
use crate::dissect::http1::dissect_http1;
use crate::dissect::l2::dissect_l2;
use crate::dissect::packet::{DissectedPacket, ProtocolFlags};

/// Dissect raw link-layer bytes into a protocol tree and summary.
pub fn dissect(data: &[u8], link_type: LinkType, keylog: Option<&KeyLog>) -> DissectedPacket {
    let mut tree = ProtoTree::new();
    let mut flags = ProtocolFlags::default();
    let mut fields = DisplayFields::new();
    let mut summary = PacketSummary {
        src: String::new(),
        dst: String::new(),
        protocol: "Data".into(),
        info: format!("{} bytes", data.len()),
        len: data.len(),
    };

    let root = tree.add_root(format!("Frame ({} bytes)", data.len()), 0, data.len());
    tree.add_child(
        root,
        "Frame length",
        format!("{}", data.len()),
        0,
        data.len(),
    );

    if data.is_empty() {
        return DissectedPacket {
            tree,
            summary,
            flags,
            expert: Vec::new(),
            payload_offset: 0,
            payload: Bytes::new(),
            decrypted: None,
            fields,
        };
    }

    let result = crate::dissect::l4::with_keylog(keylog, || {
        dissect_l2(&mut tree, root, data, link_type, &mut flags, &mut summary)
    });
    let expert = collect_expert(data, link_type, &flags, &summary);

    if summary.protocol == "Data" && !flags.any() {
        summary.info = format!("{} bytes", data.len());
    }

    populate_display_fields(&mut fields, &flags, &summary, data, link_type);

    let mut decrypted = None;
    if let Some(kl) = keylog {
        if flags.tls && kl.has_secrets() {
            let mut state = DecryptState::default();
            if let Some(plain) = decrypt_tls_in_frame(data, link_type, kl, &mut state) {
                decrypted = Some(plain.clone());
                // Re-dissect decrypted plaintext as HTTP when applicable
                if looks_like_http1(&plain) {
                    let mut sub = ProtoTree::new();
                    let sub_root = sub.add_root("Decrypted HTTP", 0, plain.len());
                    let mut sub_summary = summary.clone();
                    let _ =
                        dissect_http1(&mut sub, sub_root, &plain, 0, &mut flags, &mut sub_summary);
                    summary = sub_summary;
                    populate_display_fields(&mut fields, &flags, &summary, &plain, LinkType::Raw);
                    tree.add_child(root, "Decrypted Layer", "TLS → HTTP", 0, 0);
                }
            }
        }
    }

    DissectedPacket {
        tree,
        summary,
        flags,
        expert,
        payload_offset: result.payload_offset,
        payload: Bytes::copy_from_slice(result.payload),
        decrypted,
        fields,
    }
}

fn populate_display_fields(
    fields: &mut DisplayFields,
    flags: &ProtocolFlags,
    summary: &PacketSummary,
    data: &[u8],
    link_type: LinkType,
) {
    fields.insert("frame.protocols".into(), build_frame_protocols(flags));
    if flags.http {
        if let Some(method) = summary.info.split_whitespace().next() {
            if matches!(
                method,
                "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "OPTIONS" | "PATCH"
            ) {
                fields.insert("http.request.method".into(), method.to_string());
            }
        }
        if summary.info.starts_with("HTTP ") {
            if let Some(code) = summary.info.split_whitespace().nth(1) {
                fields.insert("http.response.code".into(), code.to_string());
            }
        }
    }
    if flags.dns {
        if let Some(rest) = summary.info.strip_prefix("Standard query ") {
            fields.insert("dns.qry.name".into(), rest.to_string());
        } else if let Some(rest) = summary.info.strip_prefix("DNS query ") {
            fields.insert("dns.qry.name".into(), rest.to_string());
        }
    }
    if flags.tls {
        if summary.info.contains("ClientHello") {
            fields.insert("tls.handshake.type".into(), "1".into());
        } else if summary.info.contains("ServerHello") {
            fields.insert("tls.handshake.type".into(), "2".into());
        }
        if let Some(cr) = extract_client_random(data, link_type) {
            fields.insert("tls.client_random".into(), cr);
        }
    }
    if flags.tcp && summary.info.contains('[') {
        if let Some(f) = summary
            .info
            .split('[')
            .nth(1)
            .and_then(|s| s.split(']').next())
        {
            if f.contains("SYN") {
                fields.insert("tcp.flags.syn".into(), "1".into());
            } else {
                fields.insert("tcp.flags.syn".into(), "0".into());
            }
        }
    }
}

fn build_frame_protocols(flags: &ProtocolFlags) -> String {
    let mut parts = Vec::new();
    if flags.ethernet {
        parts.push("eth");
    }
    if flags.vlan {
        parts.push("vlan");
    }
    if flags.ipv4 {
        parts.push("ip");
    }
    if flags.ipv6 {
        parts.push("ipv6");
    }
    if flags.tcp {
        parts.push("tcp");
    }
    if flags.udp {
        parts.push("udp");
    }
    if flags.tls {
        parts.push("tls");
    }
    if flags.http {
        parts.push("http");
    }
    if flags.http2 {
        parts.push("http2");
    }
    if flags.dns {
        parts.push("dns");
    }
    if flags.dhcp {
        parts.push("dhcp");
    }
    if flags.websocket {
        parts.push("websocket");
    }
    parts.join(":")
}

fn looks_like_http1(p: &[u8]) -> bool {
    let s = std::str::from_utf8(&p[..p.len().min(16)]).unwrap_or("");
    s.starts_with("GET ") || s.starts_with("POST ") || s.starts_with("HTTP/1.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_udp_dns() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
        let mut ip = vec![
            0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let dns = build_dns_query(b"example.com");
        let udp_len = (8 + dns.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&dns);

        let total = (20 + udp.len()) as u16;
        ip[2] = (total >> 8) as u8;
        ip[3] = (total & 0xff) as u8;
        let csum = ipv4_checksum(&ip);
        ip[10] = (csum >> 8) as u8;
        ip[11] = (csum & 0xff) as u8;

        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        pkt
    }

    fn build_dns_query(name: &[u8]) -> Vec<u8> {
        let mut d = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split(|&b| b == b'.') {
            d.push(label.len() as u8);
            d.extend_from_slice(label);
        }
        d.push(0);
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes());
        d
    }

    fn ipv4_checksum(hdr: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..hdr.len()).step_by(2) {
            if i == 10 {
                continue;
            }
            let word = if i + 1 < hdr.len() {
                u16::from_be_bytes([hdr[i], hdr[i + 1]])
            } else {
                u16::from_be_bytes([hdr[i], 0])
            };
            sum += u32::from(word);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn dissects_ethernet_ipv4_udp_dns() {
        let pkt = eth_ipv4_udp_dns();
        let d = dissect(&pkt, LinkType::Ethernet, None);
        assert!(d.flags.ethernet);
        assert!(d.flags.ipv4);
        assert!(d.flags.udp);
        assert!(d.flags.dns);
        assert_eq!(d.summary.protocol, "DNS");
        assert!(d.summary.src.contains("10.0.0.1"));
        assert!(d.fields.contains_key("frame.protocols"));
    }

    #[test]
    fn dissects_empty() {
        let d = dissect(&[], LinkType::Ethernet, None);
        assert_eq!(d.summary.len, 0);
    }

    fn eth_ipv4_tcp_syn() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]);
        let mut ip = vec![
            0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let tcp = vec![
            0x00, 0x50, 0x30, 0x39, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let total = (20 + tcp.len()) as u16;
        ip[2] = (total >> 8) as u8;
        ip[3] = (total & 0xff) as u8;
        let csum = ipv4_checksum(&ip);
        ip[10] = (csum >> 8) as u8;
        ip[11] = (csum & 0xff) as u8;
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&tcp);
        pkt
    }

    fn null_ipv4_udp_dns() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&2u32.to_le_bytes());
        let mut ip = vec![
            0x45, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let dns = build_dns_query(b"test.local");
        let udp_len = (8 + dns.len()) as u16;
        let mut udp = Vec::new();
        udp.extend_from_slice(&12345u16.to_be_bytes());
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&dns);
        let total = (20 + udp.len()) as u16;
        ip[2] = (total >> 8) as u8;
        ip[3] = (total & 0xff) as u8;
        let csum = ipv4_checksum(&ip);
        ip[10] = (csum >> 8) as u8;
        ip[11] = (csum & 0xff) as u8;
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&udp);
        pkt
    }

    #[test]
    fn dissects_ethernet_ipv4_tcp_syn() {
        let pkt = eth_ipv4_tcp_syn();
        let d = dissect(&pkt, LinkType::Ethernet, None);
        assert!(d.flags.ethernet);
        assert!(d.flags.ipv4);
        assert!(d.flags.tcp);
        assert_eq!(d.summary.protocol, "TCP");
        assert!(d.summary.info.contains("SYN"));
        assert!(d.fields.get("tcp.flags.syn").is_some_and(|v| v == "1"));
    }

    #[test]
    fn dissects_bsd_null_ipv4_udp_dns() {
        let pkt = null_ipv4_udp_dns();
        let d = dissect(&pkt, LinkType::Null, None);
        assert!(d.flags.ipv4);
        assert!(d.flags.udp);
        assert!(d.flags.dns);
        assert_eq!(d.summary.protocol, "DNS");
    }
}
