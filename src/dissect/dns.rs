//! DNS / mDNS / LLMNR dissection via hickory-proto.

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_dns<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.dns = true;
    summary.protocol = "DNS".into();
    let sec = tree.add_section(parent, "Domain Name System", offset, data.len());

    match Message::from_bytes(data) {
        Ok(msg) => {
            let qr = if msg.header().message_type() == hickory_proto::op::MessageType::Response {
                "response"
            } else {
                "query"
            };
            tree.add_child(
                sec,
                "Transaction ID",
                format!("{:#06x}", msg.header().id()),
                offset,
                2,
            );
            tree.add_child(sec, "Flags", qr.to_string(), offset + 2, 2);

            let mut names = Vec::new();
            for q in msg.queries() {
                let n = q.name().to_string();
                names.push(n.clone());
                tree.add_child(sec, "Query", format!("{} {}", n, q.query_type()), offset, 0);
            }
            for a in msg.answers() {
                tree.add_child(
                    sec,
                    "Answer",
                    format!("{} {}", a.name(), a.record_type()),
                    offset,
                    0,
                );
            }
            if names.is_empty() {
                summary.info = format!("DNS {qr}");
            } else {
                summary.info = format!("DNS {qr} {}", names.join(", "));
            }
        }
        Err(e) => {
            tree.add_child(sec, "Parse error", e.to_string(), offset, 0);
            summary.info = "DNS (malformed)".into();
        }
    }

    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}
