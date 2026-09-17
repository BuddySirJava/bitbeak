//! Network-layer dissectors: IPv4, IPv6, ICMP, ICMPv6.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dissect::l4::{dissect_tcp, dissect_udp};
use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_ipv4<'a>(
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
    flags.ipv4 = true;
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    let ttl = data[8];
    let proto = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let sec = tree.add_section(parent, "Internet Protocol Version 4", offset, ihl);
    tree.add_child(sec, "Version", "4", offset, 1);
    tree.add_child(sec, "Header Length", format!("{ihl} bytes"), offset, 1);
    tree.add_child(sec, "Total Length", format!("{total}"), offset + 2, 2);
    tree.add_child(sec, "TTL", format!("{ttl}"), offset + 8, 1);
    tree.add_child(
        sec,
        "Protocol",
        format!("{proto} ({})", proto_name(proto)),
        offset + 9,
        1,
    );
    tree.add_child(sec, "Source", src.to_string(), offset + 12, 4);
    tree.add_child(sec, "Destination", dst.to_string(), offset + 16, 4);

    summary.src = src.to_string();
    summary.dst = dst.to_string();
    summary.protocol = proto_name(proto).into();

    let end = total.min(data.len()).max(ihl);
    let payload = &data[ihl..end];
    let payload_off = offset + ihl;

    match proto {
        1 => dissect_icmp(tree, parent, payload, payload_off, flags, summary),
        6 => dissect_tcp(tree, parent, payload, payload_off, flags, summary),
        17 => dissect_udp(tree, parent, payload, payload_off, flags, summary),
        _ => {
            summary.info = format!("{} → {} proto={}", src, dst, proto_name(proto));
            LayerResult {
                payload,
                payload_offset: payload_off,
            }
        }
    }
}

pub fn dissect_ipv6<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    if data.len() < 40 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    flags.ipv6 = true;
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut next = data[6];
    let hop = data[7];
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    dst_bytes.copy_from_slice(&data[24..40]);
    let src = Ipv6Addr::from(src_bytes);
    let dst = Ipv6Addr::from(dst_bytes);

    let sec = tree.add_section(parent, "Internet Protocol Version 6", offset, 40);
    tree.add_child(
        sec,
        "Payload Length",
        format!("{payload_len}"),
        offset + 4,
        2,
    );
    tree.add_child(
        sec,
        "Next Header",
        format!("{next} ({})", proto_name(next)),
        offset + 6,
        1,
    );
    tree.add_child(sec, "Hop Limit", format!("{hop}"), offset + 7, 1);
    tree.add_child(sec, "Source", src.to_string(), offset + 8, 16);
    tree.add_child(sec, "Destination", dst.to_string(), offset + 24, 16);

    summary.src = src.to_string();
    summary.dst = dst.to_string();

    let mut cursor = 40;
    // Skip extension headers
    while let 0 | 43 | 44 | 60 = next {
        // Hop-by-Hop, Routing, Fragment, Dest Options
        if data.len() < cursor + 2 {
            break;
        }
        let hdr_len = if next == 44 {
            8
        } else {
            (data[cursor + 1] as usize + 1) * 8
        };
        let name = match next {
            0 => "IPv6 Hop-by-Hop Option",
            43 => "IPv6 Routing",
            44 => "IPv6 Fragment",
            60 => "IPv6 Destination Options",
            _ => "IPv6 Extension",
        };
        let ext = tree.add_section(
            parent,
            name,
            offset + cursor,
            hdr_len.min(data.len() - cursor),
        );
        let nh = data[cursor];
        tree.add_child(
            ext,
            "Next Header",
            format!("{nh} ({})", proto_name(nh)),
            offset + cursor,
            1,
        );
        next = nh;
        cursor += hdr_len;
        if cursor > data.len() {
            cursor = data.len();
            break;
        }
    }

    let payload = &data[cursor..];
    let payload_off = offset + cursor;
    summary.protocol = proto_name(next).into();

    match next {
        58 => dissect_icmpv6(tree, parent, payload, payload_off, flags, summary),
        6 => dissect_tcp(tree, parent, payload, payload_off, flags, summary),
        17 => dissect_udp(tree, parent, payload, payload_off, flags, summary),
        _ => {
            summary.info = format!("{} → {}", src, dst);
            LayerResult {
                payload,
                payload_offset: payload_off,
            }
        }
    }
}

fn dissect_icmp<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.icmp = true;
    summary.protocol = "ICMP".into();
    if data.len() < 4 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    let typ = data[0];
    let code = data[1];
    let sec = tree.add_section(
        parent,
        "Internet Control Message Protocol",
        offset,
        data.len(),
    );
    let type_name = icmp_type_name(typ);
    tree.add_child(sec, "Type", format!("{typ} ({type_name})"), offset, 1);
    tree.add_child(sec, "Code", format!("{code}"), offset + 1, 1);
    if data.len() >= 8 && (typ == 0 || typ == 8) {
        let id = u16::from_be_bytes([data[4], data[5]]);
        let seq = u16::from_be_bytes([data[6], data[7]]);
        tree.add_child(sec, "Identifier", format!("{id}"), offset + 4, 2);
        tree.add_child(sec, "Sequence", format!("{seq}"), offset + 6, 2);
        summary.info = format!("{type_name} id={id} seq={seq}");
    } else {
        summary.info = format!("{type_name} code={code}");
    }
    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}

fn dissect_icmpv6<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.icmpv6 = true;
    summary.protocol = "ICMPv6".into();
    if data.len() < 4 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    let typ = data[0];
    let code = data[1];
    let sec = tree.add_section(
        parent,
        "Internet Control Message Protocol v6",
        offset,
        data.len(),
    );
    let type_name = icmpv6_type_name(typ);
    tree.add_child(sec, "Type", format!("{typ} ({type_name})"), offset, 1);
    tree.add_child(sec, "Code", format!("{code}"), offset + 1, 1);

    match typ {
        128 | 129 if data.len() >= 8 => {
            let id = u16::from_be_bytes([data[4], data[5]]);
            let seq = u16::from_be_bytes([data[6], data[7]]);
            tree.add_child(sec, "Identifier", format!("{id}"), offset + 4, 2);
            tree.add_child(sec, "Sequence", format!("{seq}"), offset + 6, 2);
            summary.info = format!("{type_name} id={id} seq={seq}");
        }
        133 => summary.info = "Router Solicitation".into(),
        134 => summary.info = "Router Advertisement".into(),
        135 => {
            if data.len() >= 24 {
                let mut t = [0u8; 16];
                t.copy_from_slice(&data[8..24]);
                let target = Ipv6Addr::from(t);
                tree.add_child(sec, "Target Address", target.to_string(), offset + 8, 16);
                summary.info = format!("Neighbor Solicitation for {target}");
            } else {
                summary.info = type_name.into();
            }
        }
        136 => {
            if data.len() >= 24 {
                let mut t = [0u8; 16];
                t.copy_from_slice(&data[8..24]);
                let target = Ipv6Addr::from(t);
                tree.add_child(sec, "Target Address", target.to_string(), offset + 8, 16);
                summary.info = format!("Neighbor Advertisement {target}");
            } else {
                summary.info = type_name.into();
            }
        }
        1 if data.len() > 8 => {
            summary.info = format!("Destination Unreachable code={code}");
            // Inner IP starts at offset 8
            let _ = dissect_ipv6(
                tree,
                sec,
                &data[8..],
                offset + 8,
                &mut ProtocolFlags::default(),
                &mut PacketSummary::default(),
            );
        }
        _ => summary.info = format!("{type_name} code={code}"),
    }
    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        0 => "HOPOPT",
        43 => "IPv6-Route",
        44 => "IPv6-Frag",
        60 => "IPv6-Opts",
        _ => "Unknown",
    }
}

fn icmp_type_name(t: u8) -> &'static str {
    match t {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        _ => "Other",
    }
}

fn icmpv6_type_name(t: u8) -> &'static str {
    match t {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        128 => "Echo Request",
        129 => "Echo Reply",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        _ => "Other",
    }
}
