//! SIP and RTP dissectors (summary-level).

use crate::dissect::packet::{PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn looks_like_sip(payload: &[u8]) -> bool {
    let s = String::from_utf8_lossy(&payload[..payload.len().min(16)]);
    s.starts_with("SIP/2.0")
        || s.starts_with("INVITE ")
        || s.starts_with("REGISTER ")
        || s.starts_with("ACK ")
        || s.starts_with("BYE ")
        || s.starts_with("OPTIONS ")
        || s.starts_with("CANCEL ")
}

pub fn dissect_sip(
    tree: &mut ProtoTree,
    parent: usize,
    payload: &[u8],
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) {
    flags.sip = true;
    let text = String::from_utf8_lossy(payload);
    let first = text.lines().next().unwrap_or("SIP");
    summary.protocol = "SIP".into();
    summary.info = first.chars().take(80).collect();
    tree.add_child(parent, "SIP", first, 0, payload.len().min(64));
}

pub fn looks_like_rtp(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let v = payload[0] >> 6;
    v == 2
}

pub fn dissect_rtp(
    tree: &mut ProtoTree,
    parent: usize,
    payload: &[u8],
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) {
    if payload.len() < 12 {
        return;
    }
    flags.rtp = true;
    let pt = payload[1] & 0x7f;
    let seq = u16::from_be_bytes([payload[2], payload[3]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    summary.protocol = "RTP".into();
    summary.info = format!("PT={pt} seq={seq} SSRC={ssrc:#010x}");
    tree.add_child(parent, "RTP", summary.info.clone(), 0, 12);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_invite() {
        assert!(looks_like_sip(b"INVITE sip:a@b SIP/2.0\r\n"));
    }

    #[test]
    fn rtp_v2() {
        let mut p = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 1];
        p[0] = 0x80;
        assert!(looks_like_rtp(&p));
    }
}
