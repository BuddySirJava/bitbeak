//! Stream framing codecs for TCP/UNIX.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder, LinesCodec, LinesCodecError};

use crate::cli::{Endian, FramingKind};

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("lines codec: {0}")]
    Lines(#[from] LinesCodecError),
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
    #[error("invalid length prefix")]
    InvalidLength,
}

#[derive(Debug, Clone)]
pub struct FramingConfig {
    pub kind: FramingKind,
    pub prefix_size: u8,
    pub endian: Endian,
    pub max_frame: usize,
}

impl Default for FramingConfig {
    fn default() -> Self {
        Self {
            kind: FramingKind::None,
            prefix_size: 4,
            endian: Endian::Big,
            max_frame: 16 * 1024 * 1024,
        }
    }
}

impl FramingConfig {
    pub fn from_args(kind: FramingKind, prefix_size: u8, endian: Endian) -> Self {
        Self {
            kind,
            prefix_size: match prefix_size {
                1 | 2 | 4 | 8 => prefix_size,
                _ => 4,
            },
            endian,
            max_frame: 16 * 1024 * 1024,
        }
    }
}

/// Raw chunk framing: each read is one frame (handled outside codec).
#[derive(Debug)]
pub struct NewlineFramer {
    inner: LinesCodec,
}

impl NewlineFramer {
    pub fn new(max: usize) -> Self {
        Self {
            inner: LinesCodec::new_with_max_length(max),
        }
    }
}

impl Decoder for NewlineFramer {
    type Item = Bytes;
    type Error = FramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(self.inner.decode(src)?.map(Bytes::from))
    }
}

impl Encoder<Bytes> for NewlineFramer {
    type Error = FramingError;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut payload = item.to_vec();
        if !payload.ends_with(b"\n") {
            payload.push(b'\n');
        }
        // strip trailing newline for LinesCodec encode path — write raw
        dst.extend_from_slice(&payload);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LengthPrefixedCodec {
    prefix_size: u8,
    endian: Endian,
    max_frame: usize,
    state: LpState,
}

#[derive(Debug, Clone)]
enum LpState {
    Length,
    Body { len: usize },
}

impl LengthPrefixedCodec {
    pub fn new(prefix_size: u8, endian: Endian, max_frame: usize) -> Self {
        Self {
            prefix_size,
            endian,
            max_frame,
            state: LpState::Length,
        }
    }

    fn read_len(&self, src: &[u8]) -> Result<usize, FramingError> {
        let n = match (self.prefix_size, self.endian) {
            (1, _) => src[0] as usize,
            (2, Endian::Big) => u16::from_be_bytes([src[0], src[1]]) as usize,
            (2, Endian::Little) => u16::from_le_bytes([src[0], src[1]]) as usize,
            (4, Endian::Big) => u32::from_be_bytes(src[..4].try_into().unwrap()) as usize,
            (4, Endian::Little) => u32::from_le_bytes(src[..4].try_into().unwrap()) as usize,
            (8, Endian::Big) => {
                let v = u64::from_be_bytes(src[..8].try_into().unwrap());
                usize::try_from(v).map_err(|_| FramingError::InvalidLength)?
            }
            (8, Endian::Little) => {
                let v = u64::from_le_bytes(src[..8].try_into().unwrap());
                usize::try_from(v).map_err(|_| FramingError::InvalidLength)?
            }
            _ => return Err(FramingError::InvalidLength),
        };
        if n > self.max_frame {
            return Err(FramingError::TooLarge(n));
        }
        Ok(n)
    }

    fn write_len(&self, len: usize, dst: &mut BytesMut) -> Result<(), FramingError> {
        match (self.prefix_size, self.endian) {
            (1, _) => {
                let v = u8::try_from(len).map_err(|_| FramingError::TooLarge(len))?;
                dst.put_u8(v);
            }
            (2, Endian::Big) => {
                let v = u16::try_from(len).map_err(|_| FramingError::TooLarge(len))?;
                dst.put_u16(v);
            }
            (2, Endian::Little) => {
                let v = u16::try_from(len).map_err(|_| FramingError::TooLarge(len))?;
                dst.put_u16_le(v);
            }
            (4, Endian::Big) => {
                let v = u32::try_from(len).map_err(|_| FramingError::TooLarge(len))?;
                dst.put_u32(v);
            }
            (4, Endian::Little) => {
                let v = u32::try_from(len).map_err(|_| FramingError::TooLarge(len))?;
                dst.put_u32_le(v);
            }
            (8, Endian::Big) => dst.put_u64(len as u64),
            (8, Endian::Little) => dst.put_u64_le(len as u64),
            _ => return Err(FramingError::InvalidLength),
        }
        Ok(())
    }
}

impl Decoder for LengthPrefixedCodec {
    type Item = Bytes;
    type Error = FramingError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                LpState::Length => {
                    let n = self.prefix_size as usize;
                    if src.len() < n {
                        return Ok(None);
                    }
                    let len = self.read_len(&src[..n])?;
                    src.advance(n);
                    self.state = LpState::Body { len };
                }
                LpState::Body { len } => {
                    if src.len() < len {
                        return Ok(None);
                    }
                    let body = src.split_to(len).freeze();
                    self.state = LpState::Length;
                    return Ok(Some(body));
                }
            }
        }
    }
}

impl Encoder<Bytes> for LengthPrefixedCodec {
    type Error = FramingError;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.write_len(item.len(), dst)?;
        dst.extend_from_slice(&item);
        Ok(())
    }
}

/// Encode a payload according to framing config (for outbound).
pub fn encode_outbound(config: &FramingConfig, payload: Bytes) -> Result<Bytes, FramingError> {
    let mut buf = BytesMut::new();
    match config.kind {
        FramingKind::None => {
            buf.extend_from_slice(&payload);
        }
        FramingKind::Newline => {
            buf.extend_from_slice(&payload);
            if !payload.ends_with(b"\n") {
                buf.put_u8(b'\n');
            }
        }
        FramingKind::LengthPrefixed => {
            let mut codec =
                LengthPrefixedCodec::new(config.prefix_size, config.endian, config.max_frame);
            codec.encode(payload, &mut buf)?;
        }
    }
    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixed_roundtrip() {
        let mut codec = LengthPrefixedCodec::new(4, Endian::Big, 1024);
        let mut buf = BytesMut::new();
        codec
            .encode(Bytes::from_static(b"hello"), &mut buf)
            .unwrap();
        assert_eq!(&buf[..4], &[0, 0, 0, 5]);
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&decoded[..], b"hello");
    }

    #[test]
    fn newline_encode_adds_lf() {
        let config = FramingConfig {
            kind: FramingKind::Newline,
            ..Default::default()
        };
        let out = encode_outbound(&config, Bytes::from_static(b"ping")).unwrap();
        assert_eq!(&out[..], b"ping\n");
    }
}
