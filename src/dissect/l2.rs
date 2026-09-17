//! Link-layer dissectors: Ethernet, VLAN, ARP, Linux SLL, BSD null.

use crate::dissect::l3::dissect_ipv4;
use crate::dissect::l3::dissect_ipv6;
use crate::dissect::packet::{LayerResult, LinkType, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_l2<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    link_type: LinkType,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    match link_type {
        LinkType::Ethernet => dissect_ethernet(tree, parent, data, 0, flags, summary),
        LinkType::LinuxSll => dissect_sll(tree, parent, data, 0, flags, summary),
        LinkType::LinuxSll2 => dissect_sll2(tree, parent, data, 0, flags, summary),
        LinkType::Null => dissect_null(tree, parent, data, 0, flags, summary),
        LinkType::Raw => {
            if !data.is_empty() && (data[0] >> 4) == 4 {
                dissect_ipv4(tree, parent, data, 0, flags, summary)
            } else if !data.is_empty() && (data[0] >> 4) == 6 {
                dissect_ipv6(tree, parent, data, 0, flags, summary)
            } else {
                LayerResult {
                    payload: data,
                    payload_offset: 0,
                }
            }
        }
        LinkType::Ieee80211Radio => {
            crate::dissect::wifi::dissect_radiotap(tree, parent, data, flags, summary);
            LayerResult {
                payload: &[],
                payload_offset: data.len(),
            }
        }
        LinkType::Ieee80211 => {
            crate::dissect::wifi::dissect_dot11(tree, parent, data, flags, summary);
            LayerResult {
                payload: &[],
                payload_offset: data.len(),
            }
        }
        LinkType::Unknown(_) => {
            // Try Ethernet first
            if data.len() >= 14 {
                dissect_ethernet(tree, parent, data, 0, flags, summary)
            } else {
                LayerResult {
                    payload: data,
                    payload_offset: 0,
                }
            }
        }
    }
}

fn fmt_mac(b: &[u8]) -> String {
    if b.len() < 6 {
        return format!("{:02x?}", b);
    }
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

fn dissect_ethernet<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    if data.len() < 14 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    flags.ethernet = true;
    let eth = tree.add_section(parent, "Ethernet II", offset, 14);
    let dst = fmt_mac(&data[0..6]);
    let src = fmt_mac(&data[6..12]);
    tree.add_child(eth, "Destination", &dst, offset, 6);
    tree.add_child(eth, "Source", &src, offset + 6, 6);
    summary.src = src;
    summary.dst = dst;

    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut payload_off = offset + 14;
    tree.add_child(eth, "Type", format!("0x{ethertype:04x}"), offset + 12, 2);

    // 802.1Q VLAN
    if ethertype == 0x8100 && data.len() >= payload_off + 4 {
        flags.vlan = true;
        let vlan = tree.add_section(parent, "802.1Q Virtual LAN", payload_off, 4);
        let tci = u16::from_be_bytes([data[payload_off], data[payload_off + 1]]);
        tree.add_child(
            vlan,
            "Priority",
            format!("{}", (tci >> 13) & 0x7),
            payload_off,
            2,
        );
        tree.add_child(vlan, "VLAN ID", format!("{}", tci & 0xfff), payload_off, 2);
        ethertype = u16::from_be_bytes([data[payload_off + 2], data[payload_off + 3]]);
        tree.add_child(
            vlan,
            "Type",
            format!("0x{ethertype:04x}"),
            payload_off + 2,
            2,
        );
        payload_off += 4;
    }

    let payload = &data[payload_off.min(data.len())..];
    match ethertype {
        0x0800 => dissect_ipv4(tree, parent, payload, payload_off, flags, summary),
        0x86dd => dissect_ipv6(tree, parent, payload, payload_off, flags, summary),
        0x0806 => dissect_arp(tree, parent, payload, payload_off, flags, summary),
        _ => {
            summary.protocol = format!("0x{ethertype:04x}");
            summary.info = format!("EtherType 0x{ethertype:04x}");
            LayerResult {
                payload,
                payload_offset: payload_off,
            }
        }
    }
}

fn dissect_arp<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.arp = true;
    summary.protocol = "ARP".into();
    let sec = tree.add_section(
        parent,
        "Address Resolution Protocol",
        offset,
        data.len().min(28),
    );
    if data.len() < 8 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    let oper = u16::from_be_bytes([data[6], data[7]]);
    let op_s = match oper {
        1 => "request",
        2 => "reply",
        _ => "unknown",
    };
    tree.add_child(sec, "Opcode", format!("{oper} ({op_s})"), offset + 6, 2);

    if data.len() >= 28 {
        let sha = fmt_mac(&data[8..14]);
        let spa = format!("{}.{}.{}.{}", data[14], data[15], data[16], data[17]);
        let tha = fmt_mac(&data[18..24]);
        let tpa = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);
        tree.add_child(sec, "Sender MAC", &sha, offset + 8, 6);
        tree.add_child(sec, "Sender IP", &spa, offset + 14, 4);
        tree.add_child(sec, "Target MAC", &tha, offset + 18, 6);
        tree.add_child(sec, "Target IP", &tpa, offset + 24, 4);
        summary.src = spa.clone();
        summary.dst = tpa.clone();
        summary.info = if oper == 1 {
            format!("Who has {tpa}? Tell {spa}")
        } else {
            format!("{spa} is at {sha}")
        };
    }
    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}

fn dissect_sll<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    // Linux cooked capture v1: 16 bytes
    if data.len() < 16 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    flags.ethernet = true;
    let sec = tree.add_section(parent, "Linux cooked capture", offset, 16);
    let pkttype = u16::from_be_bytes([data[0], data[1]]);
    let protocol = u16::from_be_bytes([data[14], data[15]]);
    tree.add_child(sec, "Packet type", format!("{pkttype}"), offset, 2);
    tree.add_child(sec, "Protocol", format!("0x{protocol:04x}"), offset + 14, 2);
    let payload = &data[16..];
    let payload_off = offset + 16;
    match protocol {
        0x0800 => dissect_ipv4(tree, parent, payload, payload_off, flags, summary),
        0x86dd => dissect_ipv6(tree, parent, payload, payload_off, flags, summary),
        0x0806 => dissect_arp(tree, parent, payload, payload_off, flags, summary),
        _ => LayerResult {
            payload,
            payload_offset: payload_off,
        },
    }
}

fn dissect_sll2<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    // Linux cooked capture v2: 20 bytes
    if data.len() < 20 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    flags.ethernet = true;
    let sec = tree.add_section(parent, "Linux cooked capture v2", offset, 20);
    let protocol = u16::from_be_bytes([data[0], data[1]]);
    tree.add_child(sec, "Protocol", format!("0x{protocol:04x}"), offset, 2);
    let payload = &data[20..];
    let payload_off = offset + 20;
    match protocol {
        0x0800 => dissect_ipv4(tree, parent, payload, payload_off, flags, summary),
        0x86dd => dissect_ipv6(tree, parent, payload, payload_off, flags, summary),
        0x0806 => dissect_arp(tree, parent, payload, payload_off, flags, summary),
        _ => LayerResult {
            payload,
            payload_offset: payload_off,
        },
    }
}

fn dissect_null<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    // BSD loopback: 4-byte AF family (host endian; often little on amd64)
    if data.len() < 4 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    let sec = tree.add_section(parent, "BSD loopback", offset, 4);
    let af_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let af_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let (af, payload) = if af_le == 2 || af_le == 24 || af_le == 28 || af_le == 30 {
        (af_le, &data[4..])
    } else if af_be == 2 || af_be == 24 || af_be == 28 || af_be == 30 {
        (af_be, &data[4..])
    } else {
        (af_le, &data[4..])
    };
    tree.add_child(sec, "Family", format!("{af}"), offset, 4);
    let payload_off = offset + 4;
    match af {
        2 => dissect_ipv4(tree, parent, payload, payload_off, flags, summary),
        24 | 28 | 30 => dissect_ipv6(tree, parent, payload, payload_off, flags, summary),
        _ => {
            if !payload.is_empty() && (payload[0] >> 4) == 4 {
                dissect_ipv4(tree, parent, payload, payload_off, flags, summary)
            } else if !payload.is_empty() && (payload[0] >> 4) == 6 {
                dissect_ipv6(tree, parent, payload, payload_off, flags, summary)
            } else {
                LayerResult {
                    payload,
                    payload_offset: payload_off,
                }
            }
        }
    }
}
