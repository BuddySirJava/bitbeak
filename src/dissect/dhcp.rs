//! DHCP / BOOTP dissector.

use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_dhcp<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.dhcp = true;
    summary.protocol = "DHCP".into();
    let sec = tree.add_section(
        parent,
        "Dynamic Host Configuration Protocol",
        offset,
        data.len().min(240),
    );

    if data.len() < 240 {
        summary.info = "DHCP (truncated)".into();
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }

    let op = data[0];
    let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let yiaddr = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    let chaddr = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        data[28], data[29], data[30], data[31], data[32], data[33]
    );

    tree.add_child(
        sec,
        "Message op",
        if op == 1 { "BOOTREQUEST" } else { "BOOTREPLY" },
        offset,
        1,
    );
    tree.add_child(sec, "Transaction ID", format!("{xid:#010x}"), offset + 4, 4);
    tree.add_child(sec, "Your IP", &yiaddr, offset + 16, 4);
    tree.add_child(sec, "Client MAC", &chaddr, offset + 28, 6);

    let mut msg_type = "DHCP";
    // Options after magic cookie 0x63825363 at 236
    if data.len() > 240 && data[236..240] == [0x63, 0x82, 0x53, 0x63] {
        let mut i = 240;
        while i + 1 < data.len() {
            let code = data[i];
            if code == 255 {
                break;
            }
            if code == 0 {
                i += 1;
                continue;
            }
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }
            if code == 53 && len >= 1 {
                msg_type = match data[i + 2] {
                    1 => "Discover",
                    2 => "Offer",
                    3 => "Request",
                    4 => "Decline",
                    5 => "ACK",
                    6 => "NAK",
                    7 => "Release",
                    8 => "Inform",
                    _ => "DHCP",
                };
                tree.add_child(sec, "Option 53 Message Type", msg_type, offset + i, 2 + len);
            }
            i += 2 + len;
        }
    }

    summary.info = format!("DHCP {msg_type} xid={xid:#x} yiaddr={yiaddr} chaddr={chaddr}");
    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}
