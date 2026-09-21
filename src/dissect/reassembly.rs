//! IPv4 defragmentation and HTTP object export.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::dissect::follow::HttpObject;
use crate::dissect::packet::{LinkType, PacketRecord};

#[derive(Debug, Default)]
pub struct Ipv4Defrag {
    /// (id, src, dst, proto) -> fragments sorted by offset
    frags: BTreeMap<(u16, u32, u32, u8), Vec<FragPiece>>,
}

#[derive(Debug, Clone)]
struct FragPiece {
    offset: u16,
    more: bool,
    data: Vec<u8>,
}

impl Ipv4Defrag {
    pub fn ingest(&mut self, pkt: &PacketRecord) -> Option<Vec<u8>> {
        let (hdr, payload) = parse_ipv4(pkt)?;
        if hdr.frag_offset == 0 && !hdr.more_fragments {
            return None;
        }
        let key = (hdr.id, hdr.src, hdr.dst, hdr.proto);
        let piece = FragPiece {
            offset: hdr.frag_offset,
            more: hdr.more_fragments,
            data: payload,
        };
        self.frags.entry(key).or_default().push(piece);
        let frags = self.frags.get(&key)?;
        // Need the final fragment (MF=0) before attempting reassembly.
        if !frags.iter().any(|f| !f.more) {
            return None;
        }
        let mut sorted = frags.clone();
        sorted.sort_by_key(|f| f.offset);
        let mut out = Vec::new();
        let mut expected = 0u16;
        for f in &sorted {
            if f.offset != expected {
                return None;
            }
            out.extend_from_slice(&f.data);
            expected = expected.saturating_add(f.data.len() as u16);
        }
        // Last piece must end the datagram.
        if sorted.last().map(|f| f.more).unwrap_or(true) {
            return None;
        }
        self.frags.remove(&key);
        Some(out)
    }
}

struct Ipv4Hdr {
    id: u16,
    src: u32,
    dst: u32,
    proto: u8,
    frag_offset: u16,
    more_fragments: bool,
}

fn parse_ipv4(pkt: &PacketRecord) -> Option<(Ipv4Hdr, Vec<u8>)> {
    let data = pkt.data.as_ref();
    let ip_off = match pkt.link_type {
        LinkType::Ethernet => {
            if data.len() < 14 {
                return None;
            }
            let et = u16::from_be_bytes([data[12], data[13]]);
            if et != 0x0800 {
                return None;
            }
            14
        }
        LinkType::LinuxSll => 16,
        LinkType::Raw | LinkType::Null => 0,
        _ => return None,
    };
    if data.len() < ip_off + 20 {
        return None;
    }
    let ihl = (data[ip_off] & 0x0f) as usize * 4;
    let total = u16::from_be_bytes([data[ip_off + 2], data[ip_off + 3]]) as usize;
    let flags_frag = u16::from_be_bytes([data[ip_off + 6], data[ip_off + 7]]);
    let more = (flags_frag & 0x2000) != 0;
    let frag_off = (flags_frag & 0x1fff) * 8;
    let id = u16::from_be_bytes([data[ip_off + 4], data[ip_off + 5]]);
    let proto = data[ip_off + 9];
    let src = u32::from_be_bytes([
        data[ip_off + 12],
        data[ip_off + 13],
        data[ip_off + 14],
        data[ip_off + 15],
    ]);
    let dst = u32::from_be_bytes([
        data[ip_off + 16],
        data[ip_off + 17],
        data[ip_off + 18],
        data[ip_off + 19],
    ]);
    let end = ip_off + total.min(data.len());
    let payload = data[ip_off + ihl..end].to_vec();
    Some((
        Ipv4Hdr {
            id,
            src,
            dst,
            proto,
            frag_offset: frag_off,
            more_fragments: more,
        },
        payload,
    ))
}

/// Defragment IPv4 packets in-place order; returns reassembled pseudo-packets.
pub fn defrag_ipv4(packets: &[&PacketRecord]) -> Vec<PacketRecord> {
    let mut table = Ipv4Defrag::default();
    let mut out = Vec::new();
    for p in packets {
        if let Some(data) = table.ingest(p) {
            let mut clone = (*p).clone();
            clone.summary.info = format!("IPv4 reassembled ({} bytes)", data.len());
            out.push(clone);
        }
    }
    out
}

/// Write HTTP objects to a directory (one file per object).
pub fn export_http_objects(objects: &[HttpObject], dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).context("create export dir")?;
    for (i, obj) in objects.iter().enumerate() {
        let safe: String = obj
            .name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(40)
            .collect();
        let path = dir.join(format!("{i:04}_{safe}.bin"));
        fs::write(&path, &obj.data).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::time::{Instant, SystemTime};
    use tempfile::tempdir;

    use crate::dissect::packet::{PacketSummary, ProtocolFlags};

    fn eth_ipv4_frag(id: u16, offset_8: u16, more: bool, payload: &[u8]) -> PacketRecord {
        let mut eth = vec![0u8; 14];
        eth[12] = 0x08;
        eth[13] = 0x00;
        let ihl = 5u8;
        let total = (ihl as usize) * 4 + payload.len();
        let mut ip = vec![0u8; total];
        ip[0] = 0x45;
        ip[2] = (total >> 8) as u8;
        ip[3] = total as u8;
        ip[4] = (id >> 8) as u8;
        ip[5] = id as u8;
        let flags = if more { 0x2000u16 } else { 0 };
        let fo = flags | (offset_8 & 0x1fff);
        ip[6] = (fo >> 8) as u8;
        ip[7] = fo as u8;
        ip[9] = 17; // udp
        ip[12..16].copy_from_slice(&1u32.to_be_bytes());
        ip[16..20].copy_from_slice(&2u32.to_be_bytes());
        ip[20..].copy_from_slice(payload);
        eth.extend_from_slice(&ip);
        let len = eth.len() as u32;
        PacketRecord {
            id: 1,
            at: Instant::now(),
            wall: SystemTime::now(),
            interface: "test".into(),
            link_type: LinkType::Ethernet,
            orig_len: len,
            data: Bytes::from(eth),
            summary: PacketSummary {
                src: String::new(),
                dst: String::new(),
                protocol: "IPv4".into(),
                info: "frag".into(),
                len: len as usize,
            },
            flags: ProtocolFlags {
                ipv4: true,
                ..Default::default()
            },
            expert: Vec::new(),
            tree: None,
            decrypted: None,
            fields: HashMap::new(),
        }
    }

    #[test]
    fn ipv4_two_frags() {
        let a = eth_ipv4_frag(7, 0, true, b"AAAAAAAABBBBBBBB"); // 16 bytes
        let b = eth_ipv4_frag(7, 2, false, b"CCCCCCCC"); // offset 16 bytes = 2*8
        let mut table = Ipv4Defrag::default();
        assert!(table.ingest(&a).is_none());
        let full = table.ingest(&b).unwrap();
        assert_eq!(&full[..], b"AAAAAAAABBBBBBBBCCCCCCCC");
    }

    #[test]
    fn export_objects_writes() {
        let dir = tempdir().unwrap();
        let objs = vec![HttpObject {
            name: "index.html".into(),
            content_type: "text/html".into(),
            data: Bytes::from_static(b"<html/>"),
            is_request: false,
            method: String::new(),
            url: String::new(),
            headers: Vec::new(),
        }];
        export_http_objects(&objs, dir.path()).unwrap();
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
