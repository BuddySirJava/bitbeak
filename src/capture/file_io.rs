//! Read/write pcap and pcapng.

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgReader, PcapNgWriter};
use pcap_file::{DataLink, Endianness};

use crate::dissect::packet::{LinkType, PacketRecord};

pub struct OpenedCapture {
    pub packets: Vec<(Bytes, LinkType, u32, SystemTime)>,
}

fn link_to_datalink(link: LinkType) -> DataLink {
    match link {
        LinkType::Ethernet => DataLink::ETHERNET,
        LinkType::LinuxSll => DataLink::LINUX_SLL,
        LinkType::Null => DataLink::NULL,
        LinkType::Raw => DataLink::RAW,
        _ => DataLink::ETHERNET,
    }
}

pub fn open_capture_file(path: &Path) -> Result<OpenedCapture> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0u8; 4];
    {
        use std::io::Read;
        file.read_exact(&mut magic)?;
    }
    drop(file);
    let file = File::open(path)?;

    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        return open_pcapng(file);
    }
    open_pcap(file)
}

fn open_pcap(file: File) -> Result<OpenedCapture> {
    let mut reader = PcapReader::new(BufReader::new(file)).context("pcap reader")?;
    let header = reader.header();
    let link = LinkType::from_u32(u32::from(header.datalink));
    let mut packets = Vec::new();
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.context("read pcap packet")?;
        let wall = UNIX_EPOCH + pkt.timestamp;
        packets.push((Bytes::copy_from_slice(&pkt.data), link, pkt.orig_len, wall));
    }
    Ok(OpenedCapture { packets })
}

fn open_pcapng(file: File) -> Result<OpenedCapture> {
    let mut reader = PcapNgReader::new(BufReader::new(file)).context("pcapng reader")?;
    let mut ifaces: Vec<LinkType> = Vec::new();
    let mut packets = Vec::new();
    while let Some(block) = reader.next_block() {
        let block = block.context("pcapng block")?;
        match block {
            pcap_file::pcapng::Block::InterfaceDescription(idb) => {
                ifaces.push(LinkType::from_u32(u32::from(idb.linktype)));
            }
            pcap_file::pcapng::Block::EnhancedPacket(epb) => {
                let link = ifaces
                    .get(epb.interface_id as usize)
                    .copied()
                    .unwrap_or(LinkType::Ethernet);
                let wall = UNIX_EPOCH + epb.timestamp;
                packets.push((
                    Bytes::copy_from_slice(&epb.data),
                    link,
                    epb.original_len,
                    wall,
                ));
            }
            pcap_file::pcapng::Block::SimplePacket(sp) => {
                let link = ifaces.first().copied().unwrap_or(LinkType::Ethernet);
                packets.push((
                    Bytes::copy_from_slice(&sp.data),
                    link,
                    sp.original_len,
                    SystemTime::now(),
                ));
            }
            _ => {}
        }
    }
    Ok(OpenedCapture { packets })
}

pub fn save_packets_pcap(path: &Path, packets: &[&PacketRecord]) -> Result<()> {
    let link = packets
        .first()
        .map(|p| p.link_type)
        .unwrap_or(LinkType::Ethernet);
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: link_to_datalink(link),
        ts_resolution: pcap_file::TsResolution::MicroSecond,
        endianness: Endianness::Little,
    };
    let mut writer = PcapWriter::with_header(file, header).context("pcap header")?;
    for p in packets {
        let ts = p.wall.duration_since(UNIX_EPOCH).unwrap_or_default();
        let pkt = PcapPacket::new(ts, p.orig_len, &p.data);
        writer.write_packet(&pkt).context("write packet")?;
    }
    writer.into_writer().flush().ok();
    Ok(())
}

pub fn save_packets_pcapng(path: &Path, packets: &[&PacketRecord]) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = PcapNgWriter::new(file).context("pcapng writer")?;
    let section = SectionHeaderBlock {
        endianness: Endianness::Little,
        major_version: 1,
        minor_version: 0,
        section_length: -1,
        options: vec![],
    };
    writer
        .write_block(&section.into_block())
        .context("section")?;

    let link = packets
        .first()
        .map(|p| p.link_type)
        .unwrap_or(LinkType::Ethernet);
    let idb = InterfaceDescriptionBlock {
        linktype: link_to_datalink(link),
        snaplen: 65535,
        options: vec![],
    };
    writer.write_block(&idb.into_block()).context("iface")?;

    for p in packets {
        let ts = p.wall.duration_since(UNIX_EPOCH).unwrap_or_default();
        let epb = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: ts,
            original_len: p.orig_len,
            data: std::borrow::Cow::Borrowed(&p.data),
            options: vec![],
        };
        writer
            .write_block(&epb.into_block())
            .context("enhanced packet")?;
    }
    Ok(())
}

pub fn default_capture_path(name: &str) -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    std::env::temp_dir().join(format!("bitbeak-{name}-{ts}.pcapng"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::packet::{PacketSummary, ProtocolFlags};
    use std::time::Instant;
    use tempfile::tempdir;

    #[test]
    fn pcap_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let data = Bytes::from(vec![0u8; 64]);
        let rec = PacketRecord {
            id: 1,
            at: Instant::now(),
            wall: SystemTime::now(),
            interface: "eth0".into(),
            link_type: LinkType::Ethernet,
            orig_len: 64,
            data: data.clone(),
            summary: PacketSummary::default(),
            flags: ProtocolFlags::default(),
            expert: Vec::new(),
            tree: None,
            decrypted: None,
            fields: Default::default(),
        };
        save_packets_pcap(&path, &[&rec]).unwrap();
        let opened = open_capture_file(&path).unwrap();
        assert_eq!(opened.packets.len(), 1);
        assert_eq!(opened.packets[0].0.len(), 64);
    }
}
