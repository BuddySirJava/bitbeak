//! rpcap client (Wireshark remote capture) — framing + live capture backend.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use bytes::Bytes;

use crate::capture::backend::{CapturePacket, LiveCapture};
use crate::dissect::packet::LinkType;

/// rpcap message types (Wireshark subset).
pub const MSG_ERROR: u8 = 1;
pub const MSG_FINDALLIF_REQ: u8 = 2;
pub const MSG_OPEN_REQ: u8 = 3;
pub const MSG_STARTCAP_REQ: u8 = 4;
pub const MSG_PACKET: u8 = 7;
pub const MSG_CLOSE_REQ: u8 = 9;
pub const MSG_OPEN_REPLY: u8 = 131; // 0x80 | OPEN

/// rpcap message header (network byte order).
#[derive(Debug, Clone)]
pub struct RpcapHeader {
    pub version: u8,
    pub typ: u8,
    pub value: u16,
    pub plen: u32,
}

pub fn parse_header(buf: &[u8]) -> Option<RpcapHeader> {
    if buf.len() < 8 {
        return None;
    }
    Some(RpcapHeader {
        version: buf[0],
        typ: buf[1],
        value: u16::from_be_bytes([buf[2], buf[3]]),
        plen: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
    })
}

pub fn encode_header(typ: u8, value: u16, plen: u32) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = 0; // version
    h[1] = typ;
    h[2..4].copy_from_slice(&value.to_be_bytes());
    h[4..8].copy_from_slice(&plen.to_be_bytes());
    h
}

fn write_msg(stream: &mut TcpStream, typ: u8, value: u16, body: &[u8]) -> Result<()> {
    let hdr = encode_header(typ, value, body.len() as u32);
    stream.write_all(&hdr)?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    Ok(())
}

fn read_msg(stream: &mut TcpStream) -> Result<(RpcapHeader, Vec<u8>)> {
    let mut hdr = [0u8; 8];
    stream.read_exact(&mut hdr).context("rpcap read hdr")?;
    let h = parse_header(&hdr).context("bad rpcap hdr")?;
    if h.plen > 16 * 1024 * 1024 {
        bail!("rpcap plen too large");
    }
    let mut body = vec![0u8; h.plen as usize];
    if h.plen > 0 {
        stream.read_exact(&mut body).context("rpcap read body")?;
    }
    if h.typ == MSG_ERROR {
        let msg = String::from_utf8_lossy(&body);
        bail!("rpcap error: {msg}");
    }
    Ok((h, body))
}

/// Try open rpcap control connection and send findalldevs-style handshake (best-effort).
pub fn probe(host: &str, port: u16) -> Result<String> {
    let mut stream = TcpStream::connect((host, port)).context("rpcap connect")?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write_msg(&mut stream, MSG_FINDALLIF_REQ, 0, &[])?;
    let (rh, _) = read_msg(&mut stream)?;
    Ok(format!(
        "rpcap://{host}:{port} reply type={} value={} plen={}",
        rh.typ, rh.value, rh.plen
    ))
}

pub fn read_packet_payload(stream: &mut TcpStream) -> Result<Bytes> {
    let (h, body) = read_msg(stream)?;
    if h.typ != MSG_PACKET && h.typ != (MSG_PACKET | 0x80) {
        // Accept any payload body for tests / loose servers
    }
    Ok(Bytes::from(body))
}

/// Parse rpcap PACKET body → link-layer bytes.
/// Layout (Wireshark): timeval (8 or 16) + caplen(4) + len(4) + npkt(4) + data…
pub fn parse_packet_body(body: &[u8]) -> Result<CapturePacket> {
    // Prefer 8-byte timeval (sec+usec) + caplen + len + npkt
    if body.len() >= 20 {
        let caplen = u32::from_be_bytes([body[8], body[9], body[10], body[11]]) as usize;
        let orig = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
        let data_off = 20;
        if data_off + caplen <= body.len() {
            return Ok(CapturePacket {
                data: Bytes::copy_from_slice(&body[data_off..data_off + caplen]),
                link_type: LinkType::Ethernet,
                interface: "rpcap".into(),
                orig_len: orig.max(caplen as u32),
                wall: SystemTime::now(),
            });
        }
    }
    // Fallback: entire body is frame
    if body.is_empty() {
        bail!("empty rpcap packet");
    }
    Ok(CapturePacket {
        data: Bytes::copy_from_slice(body),
        link_type: LinkType::Ethernet,
        interface: "rpcap".into(),
        orig_len: body.len() as u32,
        wall: SystemTime::now(),
    })
}

/// Live remote capture over rpcap (read-only).
pub struct RpcapCapture {
    control: TcpStream,
    data: TcpStream,
    iface: String,
    link_type: LinkType,
}

impl RpcapCapture {
    /// Connect to `host:port`, open `iface`, start capture on data channel.
    pub fn open(host: &str, port: u16, iface: &str) -> Result<Self> {
        let mut control = TcpStream::connect((host, port)).context("rpcap control connect")?;
        control.set_read_timeout(Some(Duration::from_secs(5)))?;
        control.set_write_timeout(Some(Duration::from_secs(5)))?;
        control.set_nonblocking(false)?;

        // OPEN request: iface name as C string body
        let mut open_body = iface.as_bytes().to_vec();
        open_body.push(0);
        write_msg(&mut control, MSG_OPEN_REQ, 0, &open_body)?;
        let (open_reply, _) = read_msg(&mut control)?;
        if open_reply.typ != MSG_OPEN_REPLY && open_reply.typ != (MSG_OPEN_REQ | 0x80) {
            // Some servers use different reply codes — continue if not ERROR
        }

        // STARTCAP: snaplen=65535, timeout=500ms, flags=0 — simplified fixed body
        let mut start_body = Vec::new();
        start_body.extend_from_slice(&65535u32.to_be_bytes()); // snaplen
        start_body.extend_from_slice(&500u32.to_be_bytes()); // read timeout ms
        start_body.extend_from_slice(&0u16.to_be_bytes()); // flags
        start_body.extend_from_slice(&0u16.to_be_bytes()); // client port (0 = same conn / server assigns)
        write_msg(&mut control, MSG_STARTCAP_REQ, 0, &start_body)?;
        let (start_reply, start_payload) = read_msg(&mut control)?;

        // STARTCAP reply often contains: bufsize(4) + porthi/portlo or server port
        let data_port = if start_payload.len() >= 6 {
            u16::from_be_bytes([start_payload[4], start_payload[5]])
        } else if start_reply.value != 0 {
            start_reply.value
        } else {
            0
        };

        let data = if data_port > 0 && data_port != port {
            let d = TcpStream::connect((host, data_port)).context("rpcap data connect")?;
            d.set_read_timeout(Some(Duration::from_millis(200)))?;
            d.set_nonblocking(true)?;
            d
        } else {
            // Same connection for packets (best-effort)
            let d = control.try_clone().context("rpcap clone")?;
            d.set_read_timeout(Some(Duration::from_millis(200)))?;
            let _ = d.set_nonblocking(true);
            d
        };

        control.set_nonblocking(true)?;

        Ok(Self {
            control,
            data,
            iface: format!("rpcap://{host}:{port}/{iface}"),
            link_type: LinkType::Ethernet,
        })
    }
}

impl LiveCapture for RpcapCapture {
    fn next_packet(&mut self) -> Result<Option<CapturePacket>> {
        match read_msg(&mut self.data) {
            Ok((h, body)) => {
                if h.typ == MSG_PACKET || h.typ == (MSG_PACKET | 0x80) || !body.is_empty() {
                    let mut pkt = parse_packet_body(&body)?;
                    pkt.interface = self.iface.clone();
                    pkt.link_type = self.link_type;
                    Ok(Some(pkt))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                let io = e.downcast_ref::<std::io::Error>();
                if let Some(err) = io {
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut
                    {
                        return Ok(None);
                    }
                }
                // Also treat "rpcap read hdr" WouldBlock wrapped
                let msg = format!("{e:#}");
                if msg.contains("WouldBlock")
                    || msg.contains("timed out")
                    || msg.contains("Timeout")
                {
                    return Ok(None);
                }
                Err(e)
            }
        }
    }

    fn inject(&mut self, _frame: &[u8]) -> Result<()> {
        bail!("rpcap inject not supported (read-only)")
    }

    fn interface(&self) -> &str {
        &self.iface
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }
}

impl Drop for RpcapCapture {
    fn drop(&mut self) {
        let _ = write_msg(&mut self.control, MSG_CLOSE_REQ, 0, &[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = encode_header(2, 7, 12);
        let p = parse_header(&h).unwrap();
        assert_eq!(p.typ, 2);
        assert_eq!(p.value, 7);
        assert_eq!(p.plen, 12);
    }

    #[test]
    fn parse_packet_body_with_header() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // sec
        body.extend_from_slice(&0u32.to_be_bytes()); // usec
        body.extend_from_slice(&4u32.to_be_bytes()); // caplen
        body.extend_from_slice(&4u32.to_be_bytes()); // len
        body.extend_from_slice(&1u32.to_be_bytes()); // npkt
        body.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let pkt = parse_packet_body(&body).unwrap();
        assert_eq!(&pkt.data[..], &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(pkt.orig_len, 4);
    }
}
