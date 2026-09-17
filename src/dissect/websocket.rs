//! WebSocket frame dissector.

use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_websocket<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.websocket = true;
    summary.protocol = "WebSocket".into();
    if data.len() < 2 {
        return LayerResult {
            payload: data,
            payload_offset: offset,
        };
    }
    let sec = tree.add_section(parent, "WebSocket", offset, data.len());
    let fin = (data[0] & 0x80) != 0;
    let opcode = data[0] & 0x0f;
    let masked = (data[1] & 0x80) != 0;
    let mut plen = (data[1] & 0x7f) as usize;
    let mut hdr = 2usize;
    if plen == 126 && data.len() >= 4 {
        plen = u16::from_be_bytes([data[2], data[3]]) as usize;
        hdr = 4;
    } else if plen == 127 && data.len() >= 10 {
        plen = u64::from_be_bytes([
            data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
        ]) as usize;
        hdr = 10;
    }
    if masked {
        hdr += 4;
    }
    let op_name = match opcode {
        0x0 => "Continuation",
        0x1 => "Text",
        0x2 => "Binary",
        0x8 => "Close",
        0x9 => "Ping",
        0xa => "Pong",
        _ => "Unknown",
    };
    tree.add_child(sec, "FIN", format!("{fin}"), offset, 1);
    tree.add_child(sec, "Opcode", format!("{opcode} ({op_name})"), offset, 1);
    tree.add_child(sec, "Masked", format!("{masked}"), offset + 1, 1);
    tree.add_child(sec, "Payload length", format!("{plen}"), offset + 1, 1);
    summary.info = format!("WebSocket {op_name} len={plen}");
    LayerResult {
        payload: if data.len() > hdr { &data[hdr..] } else { &[] },
        payload_offset: offset + hdr,
    }
}
