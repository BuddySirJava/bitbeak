//! Rotating pcapng disk ring while capturing.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
use pcap_file::{DataLink, Endianness};

use crate::dissect::packet::{LinkType, PacketRecord};

pub struct DiskRing {
    dir: PathBuf,
    prefix: String,
    max_bytes: u64,
    max_files: usize,
    current_idx: usize,
    current_bytes: u64,
    writer: Option<PcapNgWriter<File>>,
    wrote_iface: bool,
}

impl DiskRing {
    pub fn new(dir: impl AsRef<Path>, prefix: &str, max_mb: u64, max_files: usize) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let mut ring = Self {
            dir,
            prefix: prefix.to_string(),
            max_bytes: max_mb.max(1) * 1024 * 1024,
            max_files: max_files.max(1),
            current_idx: 0,
            current_bytes: 0,
            writer: None,
            wrote_iface: false,
        };
        ring.rotate()?;
        Ok(ring)
    }

    fn path_for(&self, idx: usize) -> PathBuf {
        self.dir.join(format!(
            "{}-{:05}.pcapng",
            self.prefix,
            idx % self.max_files
        ))
    }

    fn rotate(&mut self) -> Result<()> {
        self.writer = None;
        self.wrote_iface = false;
        self.current_bytes = 0;
        let path = self.path_for(self.current_idx);
        let file =
            File::create(&path).with_context(|| format!("create ring file {}", path.display()))?;
        let mut writer = PcapNgWriter::new(file).context("pcapng")?;
        let section = SectionHeaderBlock {
            endianness: Endianness::Little,
            major_version: 1,
            minor_version: 0,
            section_length: -1,
            options: vec![],
        };
        writer.write_block(&section.into_block())?;
        self.writer = Some(writer);
        self.current_idx += 1;
        Ok(())
    }

    pub fn write_packet(&mut self, pkt: &PacketRecord) -> Result<()> {
        if self.current_bytes >= self.max_bytes {
            self.rotate()?;
        }
        let writer = self.writer.as_mut().context("no ring writer")?;
        if !self.wrote_iface {
            let idb = InterfaceDescriptionBlock {
                linktype: match pkt.link_type {
                    LinkType::Ethernet => DataLink::ETHERNET,
                    LinkType::LinuxSll => DataLink::LINUX_SLL,
                    LinkType::Null => DataLink::NULL,
                    _ => DataLink::ETHERNET,
                },
                snaplen: 65535,
                options: vec![],
            };
            writer.write_block(&idb.into_block())?;
            self.wrote_iface = true;
        }
        let ts = pkt.wall.duration_since(UNIX_EPOCH).unwrap_or_default();
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: ts,
            original_len: pkt.orig_len,
            data: std::borrow::Cow::Borrowed(&pkt.data),
            options: vec![],
        };
        let n = writer.write_block(&epb.into_block())?;
        self.current_bytes += n as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::packet::{PacketSummary, ProtocolFlags};
    use bytes::Bytes;
    use std::time::{Instant, SystemTime};
    use tempfile::tempdir;

    #[test]
    fn rotates_on_tiny_limit() {
        let dir = tempdir().unwrap();
        let mut ring = DiskRing::new(dir.path(), "t", 1, 3).unwrap();
        let rec = PacketRecord {
            id: 1,
            at: Instant::now(),
            wall: SystemTime::now(),
            interface: "eth0".into(),
            link_type: LinkType::Ethernet,
            orig_len: 64,
            data: Bytes::from(vec![0u8; 64]),
            summary: PacketSummary::default(),
            flags: ProtocolFlags::default(),
            expert: Vec::new(),
            tree: None,
            decrypted: None,
            fields: Default::default(),
        };
        ring.write_packet(&rec).unwrap();
        assert!(dir.path().join("t-00000.pcapng").exists());
    }
}
