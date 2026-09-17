//! Frame model, ring buffer, preview, and filter.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub fn arrow(self) -> &'static str {
        match self {
            Self::In => "<-",
            Self::Out => "->",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub id: u64,
    pub at: Instant,
    pub wall: SystemTime,
    pub direction: Direction,
    pub payload: Bytes,
    pub peer: Option<String>,
    pub meta: Option<String>,
}

impl Frame {
    pub fn new(id: u64, direction: Direction, payload: impl Into<Bytes>) -> Self {
        Self {
            id,
            at: Instant::now(),
            wall: SystemTime::now(),
            direction,
            payload: payload.into(),
            peer: None,
            meta: None,
        }
    }

    pub fn size(&self) -> usize {
        self.payload.len()
    }

    pub fn wall_hms_millis(&self) -> String {
        let dur = self
            .wall
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let total_secs = dur.as_secs();
        let millis = dur.subsec_millis();
        let secs = total_secs % 60;
        let mins = (total_secs / 60) % 60;
        let hours = (total_secs / 3600) % 24;
        format!("{hours:02}:{mins:02}:{secs:02}.{millis:03}")
    }

    pub fn preview(&self, max: usize) -> String {
        preview_bytes(&self.payload, max)
    }

    pub fn matches_filter(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.trim();
        if let Some(hex) = q.strip_prefix("hex:") {
            return match parse_hex_bytes(hex.trim()) {
                Ok(needle) => {
                    !needle.is_empty()
                        && self
                            .payload
                            .windows(needle.len())
                            .any(|w| w == needle.as_slice())
                }
                Err(_) => false,
            };
        }
        if let Some(dir) = q.strip_prefix("dir:") {
            let d = dir.trim().to_ascii_lowercase();
            return match d.as_str() {
                "in" | "<-" | "rx" => self.direction == Direction::In,
                "out" | "->" | "tx" => self.direction == Direction::Out,
                _ => false,
            };
        }
        let lower = q.to_ascii_lowercase();
        let preview = self.preview(256).to_ascii_lowercase();
        if preview.contains(&lower) {
            return true;
        }
        if let Ok(text) = std::str::from_utf8(&self.payload) {
            if text.to_ascii_lowercase().contains(&lower) {
                return true;
            }
        }
        if let Some(peer) = &self.peer {
            if peer.to_ascii_lowercase().contains(&lower) {
                return true;
            }
        }
        false
    }
}

pub fn preview_bytes(payload: &[u8], max: usize) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for &b in payload {
        if out.len() >= max {
            out.push('…');
            break;
        }
        match b {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit {}", b as char)),
    }
}

#[derive(Debug)]
pub struct FrameBuffer {
    frames: VecDeque<Frame>,
    capacity: usize,
    next_id: u64,
}

impl FrameBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(capacity.min(1024)),
            capacity: capacity.max(1),
            next_id: 1,
        }
    }

    pub fn push(&mut self, direction: Direction, payload: impl Into<Bytes>) -> &Frame {
        self.push_full(direction, payload, None, None)
    }

    pub fn push_full(
        &mut self,
        direction: Direction,
        payload: impl Into<Bytes>,
        peer: Option<String>,
        meta: Option<String>,
    ) -> &Frame {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let mut frame = Frame::new(id, direction, payload);
        frame.peer = peer;
        frame.meta = meta;
        if self.frames.len() >= self.capacity {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
        self.frames.back().expect("just pushed")
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Frame> {
        self.frames.iter()
    }

    pub fn get(&self, index: usize) -> Option<&Frame> {
        self.frames.get(index)
    }

    pub fn get_by_id(&self, id: u64) -> Option<&Frame> {
        self.frames.iter().find(|f| f.id == id)
    }

    pub fn filtered<'a>(&'a self, query: &'a str) -> Vec<&'a Frame> {
        self.frames
            .iter()
            .filter(|f| f.matches_filter(query))
            .collect()
    }

    pub fn all(&self) -> Vec<&Frame> {
        self.frames.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_escapes_binary() {
        let s = preview_bytes(b"hi\x00\xff", 64);
        assert_eq!(s, "hi\\x00\\xff");
    }

    #[test]
    fn filter_hex() {
        let mut buf = FrameBuffer::new(10);
        buf.push(Direction::Out, b"\x01\x02\x03".as_slice());
        assert!(buf.filtered("hex:0102").len() == 1);
        assert!(buf.filtered("hex:ff").is_empty());
    }

    #[test]
    fn ring_drops_oldest() {
        let mut buf = FrameBuffer::new(2);
        buf.push(Direction::In, b"a".as_slice());
        buf.push(Direction::In, b"b".as_slice());
        buf.push(Direction::In, b"c".as_slice());
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.get(0).unwrap().payload.as_ref(), b"b");
    }

    #[test]
    fn parse_hex() {
        assert_eq!(parse_hex_bytes("0a:0B-0c").unwrap(), vec![0x0a, 0x0b, 0x0c]);
    }
}
