//! Multi-format payload inspector.

use crc32fast::Hasher;
use ratatui::text::{Line, Span};
use rmpv::Value;
use serde_json::Value as JsonValue;

use crate::ui::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InspectMode {
    #[default]
    Hex,
    Raw,
    Json,
    MsgPack,
}

impl InspectMode {
    pub fn next(self) -> Self {
        match self {
            Self::Hex => Self::Raw,
            Self::Raw => Self::Json,
            Self::Json => Self::MsgPack,
            Self::MsgPack => Self::Hex,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Hex => Self::MsgPack,
            Self::Raw => Self::Hex,
            Self::Json => Self::Raw,
            Self::MsgPack => Self::Json,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Raw => "Raw",
            Self::Json => "JSON",
            Self::MsgPack => "MsgP",
        }
    }

    pub fn all() -> [Self; 4] {
        [Self::Hex, Self::Raw, Self::Json, Self::MsgPack]
    }
}

pub fn crc32(payload: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(payload);
    h.finalize()
}

pub fn hex_dump(payload: &[u8], max_lines: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, chunk) in payload.chunks(16).enumerate() {
        if i >= max_lines {
            lines.push(format!(
                "… {} more bytes",
                payload.len().saturating_sub(i * 16)
            ));
            break;
        }
        let offset = i * 16;
        let mut hex = String::new();
        let mut ascii = String::new();
        for (j, &b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        while hex.len() < 49 {
            hex.push(' ');
        }
        lines.push(format!("{offset:04x}: {hex} {ascii}"));
    }
    if lines.is_empty() {
        lines.push("(empty)".into());
    }
    lines
}

pub fn raw_text(payload: &[u8]) -> String {
    crate::frame::preview_bytes(payload, usize::MAX)
}

pub fn json_pretty(payload: &[u8]) -> Result<String, String> {
    let v: JsonValue = serde_json::from_slice(payload).map_err(|e| format!("invalid JSON: {e}"))?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

pub fn msgpack_pretty(payload: &[u8]) -> Result<String, String> {
    let mut cur = payload;
    let value =
        rmpv::decode::read_value(&mut cur).map_err(|e| format!("invalid MessagePack: {e}"))?;
    Ok(format_msgpack(&value, 0))
}

fn format_msgpack(v: &Value, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match v {
        Value::Nil => format!("{pad}null"),
        Value::Boolean(b) => format!("{pad}{b}"),
        Value::Integer(i) => format!("{pad}{i}"),
        Value::F32(f) => format!("{pad}{f}"),
        Value::F64(f) => format!("{pad}{f}"),
        Value::String(s) => format!("{pad}\"{}\"", s.as_str().unwrap_or("")),
        Value::Binary(b) => format!("{pad}<bin {} bytes>", b.len()),
        Value::Array(arr) => {
            let mut out = format!("{pad}[\n");
            for item in arr {
                out.push_str(&format_msgpack(item, indent + 1));
                out.push('\n');
            }
            out.push_str(&format!("{pad}]"));
            out
        }
        Value::Map(map) => {
            let mut out = format!("{pad}{{\n");
            for (k, val) in map {
                out.push_str(&format_msgpack(k, indent + 1));
                out.push_str(": ");
                let nested = format_msgpack(val, 0).trim().to_string();
                if nested.contains('\n') {
                    out.push('\n');
                    out.push_str(&format_msgpack(val, indent + 1));
                } else {
                    out.push_str(&nested);
                }
                out.push('\n');
            }
            out.push_str(&format!("{pad}}}"));
            out
        }
        Value::Ext(tag, data) => format!("{pad}<ext {tag} {} bytes>", data.len()),
    }
}

pub fn render(
    mode: InspectMode,
    payload: &[u8],
    max_lines: usize,
) -> (Vec<String>, Option<String>) {
    match mode {
        InspectMode::Hex => (hex_dump(payload, max_lines), None),
        InspectMode::Raw => {
            let text = raw_text(payload);
            let lines: Vec<String> = text.lines().map(str::to_string).collect();
            let lines = if lines.is_empty() {
                vec![text]
            } else {
                lines.into_iter().take(max_lines).collect()
            };
            (lines, None)
        }
        InspectMode::Json => match json_pretty(payload) {
            Ok(s) => (
                s.lines().map(str::to_string).take(max_lines).collect(),
                None,
            ),
            Err(e) => (hex_dump(payload, max_lines.min(8)), Some(e)),
        },
        InspectMode::MsgPack => match msgpack_pretty(payload) {
            Ok(s) => (
                s.lines().map(str::to_string).take(max_lines).collect(),
                None,
            ),
            Err(e) => (hex_dump(payload, max_lines.min(8)), Some(e)),
        },
    }
}

/// Colorized inspector lines (JSON / MsgPack get token colors).
pub fn render_lines(
    mode: InspectMode,
    payload: &[u8],
    max_lines: usize,
) -> (Vec<Line<'static>>, Option<String>) {
    match mode {
        InspectMode::Json => match json_pretty(payload) {
            Ok(s) => (
                s.lines().take(max_lines).map(colorize_json_line).collect(),
                None,
            ),
            Err(e) => (
                hex_dump(payload, max_lines.min(8))
                    .into_iter()
                    .map(|l| Line::from(Span::styled(l, theme::value())))
                    .collect(),
                Some(e),
            ),
        },
        InspectMode::MsgPack => match msgpack_pretty(payload) {
            Ok(s) => (
                s.lines().take(max_lines).map(colorize_json_line).collect(),
                None,
            ),
            Err(e) => (
                hex_dump(payload, max_lines.min(8))
                    .into_iter()
                    .map(|l| Line::from(Span::styled(l, theme::value())))
                    .collect(),
                Some(e),
            ),
        },
        other => {
            let (lines, err) = render(other, payload, max_lines);
            (
                lines
                    .into_iter()
                    .map(|l| Line::from(Span::styled(l, theme::value())))
                    .collect(),
                err,
            )
        }
    }
}

fn colorize_json_line(line: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '"' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let s = &line[start..i];
            let rest = line[i..].trim_start();
            let style = if rest.starts_with(':') {
                theme::json_key()
            } else {
                theme::json_string()
            };
            spans.push(Span::styled(s.to_string(), style));
        } else if c.is_ascii_digit()
            || (c == '-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit())
        {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit()
                    || matches!(bytes[i], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                i += 1;
            }
            spans.push(Span::styled(
                line[start..i].to_string(),
                theme::json_number(),
            ));
        } else if line[i..].starts_with("true")
            || line[i..].starts_with("false")
            || line[i..].starts_with("null")
        {
            let lit = if line[i..].starts_with("true") {
                "true"
            } else if line[i..].starts_with("false") {
                "false"
            } else {
                "null"
            };
            spans.push(Span::styled(lit.to_string(), theme::json_literal()));
            i += lit.len();
        } else {
            let start = i;
            i += 1;
            while i < bytes.len() {
                let ch = bytes[i] as char;
                if ch == '"'
                    || ch.is_ascii_digit()
                    || line[i..].starts_with("true")
                    || line[i..].starts_with("false")
                    || line[i..].starts_with("null")
                    || (ch == '-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit())
                {
                    break;
                }
                i += 1;
            }
            spans.push(Span::styled(line[start..i].to_string(), theme::value()));
        }
    }
    if spans.is_empty() {
        Line::from(Span::styled(line.to_string(), theme::value()))
    } else {
        Line::from(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_ok() {
        let s = json_pretty(br#"{"a":1}"#).unwrap();
        assert!(s.contains("\"a\""));
    }

    #[test]
    fn json_err() {
        assert!(json_pretty(b"not json").is_err());
    }

    #[test]
    fn msgpack_nil() {
        let pretty = msgpack_pretty(&[0xc0]).unwrap();
        assert!(pretty.contains("null"));
    }

    #[test]
    fn crc_stable() {
        assert_eq!(crc32(b"hello"), crc32(b"hello"));
    }

    #[test]
    fn colorize_has_spans() {
        let line = colorize_json_line(r#"  "a": 1,"#);
        assert!(line.spans.len() >= 2);
    }
}
