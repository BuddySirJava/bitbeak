//! Radiotap + 802.11 management frame summary.

use crate::dissect::packet::ProtocolFlags;
use crate::dissect::tree::ProtoTree;

pub fn dissect_radiotap(
    tree: &mut ProtoTree,
    parent: usize,
    data: &[u8],
    flags: &mut ProtocolFlags,
    summary: &mut crate::dissect::packet::PacketSummary,
) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let it_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if it_len > data.len() {
        return None;
    }
    flags.wifi = true;
    let node = tree.add_child(parent, "Radiotap", format!("hdr {it_len} B"), 0, it_len);
    let _ = node;
    let wifi = &data[it_len..];
    dissect_dot11(tree, parent, wifi, flags, summary);
    Some(it_len)
}

pub fn dissect_dot11(
    tree: &mut ProtoTree,
    parent: usize,
    data: &[u8],
    flags: &mut ProtocolFlags,
    summary: &mut crate::dissect::packet::PacketSummary,
) {
    if data.len() < 24 {
        return;
    }
    flags.wifi = true;
    let fc = u16::from_le_bytes([data[0], data[1]]);
    let ftype = (fc >> 2) & 0x3;
    let subtype = (fc >> 4) & 0xf;
    let type_name = match ftype {
        0 => "Mgmt",
        1 => "Ctrl",
        2 => "Data",
        _ => "Ext",
    };
    let subtype_name = match (ftype, subtype) {
        (0, 8) => "Beacon",
        (0, 4) => "Probe Req",
        (0, 5) => "Probe Resp",
        (0, 11) => "Auth",
        (0, 0) => "Assoc Req",
        (2, _) => "Data",
        _ => "Other",
    };
    summary.protocol = "802.11".into();
    summary.info = format!("{type_name}/{subtype_name}");
    tree.add_child(
        parent,
        "802.11",
        format!("{type_name}/{subtype_name}"),
        0,
        data.len().min(24),
    );
    // Beacon SSID IE
    if ftype == 0 && subtype == 8 && data.len() > 36 {
        if let Some(ssid) = find_ssid(&data[36..]) {
            summary.info = format!("Beacon SSID={ssid}");
            tree.add_child(parent, "SSID", ssid, 36, 0);
        }
    }
}

fn find_ssid(ies: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        i += 2;
        if i + len > ies.len() {
            break;
        }
        if id == 0 {
            return Some(String::from_utf8_lossy(&ies[i..i + len]).into_owned());
        }
        i += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::packet::{PacketSummary, ProtocolFlags};
    use crate::dissect::tree::ProtoTree;

    #[test]
    fn beacon_ssid() {
        // minimal fake: radiotap 8 bytes + mgmt beacon with SSID IE "x"
        let mut data = vec![0u8; 8];
        data[2] = 8; // it_len
                     // 802.11 hdr 24 + fixed 12 + IE
        let mut wifi = vec![0u8; 36];
        wifi[0] = 0x80; // beacon
        wifi.extend_from_slice(&[0, 1, b'x']); // SSID IE
        data.extend_from_slice(&wifi);
        let mut tree = ProtoTree::new();
        let root = tree.add_root("f", 0, data.len());
        let mut flags = ProtocolFlags::default();
        let mut summary = PacketSummary {
            src: String::new(),
            dst: String::new(),
            protocol: String::new(),
            info: String::new(),
            len: data.len(),
        };
        dissect_radiotap(&mut tree, root, &data, &mut flags, &mut summary);
        assert!(flags.wifi);
        assert!(summary.info.contains("SSID"));
    }
}
