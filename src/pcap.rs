//! Write reconstructed pcap files from application frames (no libpcap).

use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::DataLink;

use crate::frame::{Direction, Frame};

/// Export frames to a classic pcap with fake Ethernet/IPv4/TCP headers.
pub fn write_frames_pcap(
    path: &Path,
    frames: &[&Frame],
    src: SocketAddrV4,
    dst: SocketAddrV4,
) -> Result<()> {
    let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::MicroSecond,
        endianness: pcap_file::Endianness::Little,
    };
    let mut writer = PcapWriter::with_header(file, header).context("pcap header")?;

    for frame in frames {
        let (s, d) = match frame.direction {
            Direction::Out => (src, dst),
            Direction::In => (dst, src),
        };
        let packet = build_tcp_packet(s, d, &frame.payload, frame.id as u32);
        let ts = frame.wall.duration_since(UNIX_EPOCH).unwrap_or_default();
        let pkt = PcapPacket::new(ts, packet.len() as u32, &packet);
        writer.write_packet(&pkt).context("write packet")?;
    }
    writer.into_writer().flush().ok();
    Ok(())
}

fn build_tcp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8], seq: u32) -> Vec<u8> {
    let mut eth = vec![
        // dst mac
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src mac
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // ethertype IPv4
        0x08, 0x00,
    ];
    let ip_payload_len = 20 + payload.len(); // TCP hdr + data
    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // v4, ihl=5
    ip.push(0); // tos
    let total = (20 + ip_payload_len) as u16;
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.push(64); // ttl
    ip.push(6); // TCP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&src.ip().octets());
    ip.extend_from_slice(&dst.ip().octets());
    let csum = ip_checksum(&ip);
    ip[10] = (csum >> 8) as u8;
    ip[11] = (csum & 0xff) as u8;

    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port().to_be_bytes());
    tcp.extend_from_slice(&dst.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(0x50); // data offset 5
    tcp.push(0x18); // PSH+ACK
    tcp.extend_from_slice(&8192u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
    tcp.extend_from_slice(payload);

    eth.extend_from_slice(&ip);
    eth.extend_from_slice(&tcp);
    eth
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn default_addrs() -> (SocketAddrV4, SocketAddrV4) {
    (
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 80),
    )
}

/// Record path helper under config dir.
pub fn default_pcap_path(name: &str) -> std::path::PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    std::env::temp_dir().join(format!("bitbeak-{name}-{ts}.pcap"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Direction, FrameBuffer};
    use tempfile::tempdir;

    #[test]
    fn writes_readable_pcap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let mut buf = FrameBuffer::new(10);
        buf.push(Direction::Out, b"hello".as_slice());
        buf.push(Direction::In, b"world".as_slice());
        let frames = buf.all();
        let (s, d) = default_addrs();
        write_frames_pcap(&path, &frames, s, d).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() > 24);
    }
}
