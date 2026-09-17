//! Composer payload encode/decode (UTF-8 escapes and hex mode).

use crate::frame::parse_hex_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComposerMode {
    #[default]
    Utf8,
    Hex,
}

/// Decode composer text into raw bytes.
pub fn decode_payload(text: &str, mode: ComposerMode) -> Result<Vec<u8>, String> {
    match mode {
        ComposerMode::Utf8 => decode_utf8_escapes(text),
        ComposerMode::Hex => parse_hex_bytes(text),
    }
}

/// Encode bytes for editing in the composer.
pub fn encode_for_edit(payload: &[u8], mode: ComposerMode) -> String {
    match mode {
        ComposerMode::Utf8 => {
            if let Ok(s) = std::str::from_utf8(payload) {
                if s.chars()
                    .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
                {
                    return s.to_string();
                }
            }
            let mut out = String::new();
            for &b in payload {
                match b {
                    b'\n' => out.push_str("\\n"),
                    b'\r' => out.push_str("\\r"),
                    b'\t' => out.push_str("\\t"),
                    b'\\' => out.push_str("\\\\"),
                    0x20..=0x7e => out.push(b as char),
                    _ => out.push_str(&format!("\\x{b:02x}")),
                }
            }
            out
        }
        ComposerMode::Hex => payload
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn decode_utf8_escapes(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return Err("trailing backslash".into());
            }
            match bytes[i] {
                b'n' => {
                    out.push(b'\n');
                    i += 1;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 1;
                }
                b't' => {
                    out.push(b'\t');
                    i += 1;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 1;
                }
                b'x' => {
                    i += 1;
                    if i + 1 >= bytes.len() {
                        return Err("incomplete \\x escape".into());
                    }
                    let hi = hex_digit(bytes[i])?;
                    let lo = hex_digit(bytes[i + 1])?;
                    out.push((hi << 4) | lo);
                    i += 2;
                }
                other => {
                    out.push(b'\\');
                    out.push(other);
                    i += 1;
                }
            }
        } else {
            // copy UTF-8 character as-is (may be multi-byte)
            let ch = text[i..]
                .chars()
                .next()
                .ok_or_else(|| "invalid utf-8".to_string())?;
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            out.extend_from_slice(encoded.as_bytes());
            i += ch.len_utf8();
        }
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit {}", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_escapes() {
        assert_eq!(
            decode_payload(r#"hi\x00\n"#, ComposerMode::Utf8).unwrap(),
            b"hi\x00\n"
        );
    }

    #[test]
    fn decode_hex_mode() {
        assert_eq!(
            decode_payload("01 02 ff", ComposerMode::Hex).unwrap(),
            vec![1, 2, 255]
        );
    }

    #[test]
    fn roundtrip_edit() {
        let raw = b"{\"a\":1}\n";
        let s = encode_for_edit(raw, ComposerMode::Utf8);
        assert_eq!(decode_payload(&s, ComposerMode::Utf8).unwrap(), raw);
    }
}
