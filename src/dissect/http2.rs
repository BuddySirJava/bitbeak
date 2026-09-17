//! HTTP/2 frame dissector (no full stream state beyond HPACK best-effort).

use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub fn dissect_http2<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.http2 = true;
    summary.protocol = "HTTP2".into();
    let sec = tree.add_section(parent, "HyperText Transfer Protocol 2", offset, data.len());

    let mut cur = 0usize;
    if data.starts_with(PREFACE) {
        tree.add_child(
            sec,
            "Connection Preface",
            "PRI * HTTP/2.0",
            offset,
            PREFACE.len(),
        );
        cur = PREFACE.len();
    }

    let mut infos = Vec::new();
    let mut decoder = hpack::Decoder::new();

    while cur + 9 <= data.len() {
        let len =
            ((data[cur] as usize) << 16) | ((data[cur + 1] as usize) << 8) | data[cur + 2] as usize;
        let typ = data[cur + 3];
        let fl = data[cur + 4];
        let stream = u32::from_be_bytes([
            data[cur + 5] & 0x7f,
            data[cur + 6],
            data[cur + 7],
            data[cur + 8],
        ]);
        let frame_end = cur + 9 + len;
        if frame_end > data.len() {
            tree.add_child(
                sec,
                "Truncated frame",
                format!("type={typ} len={len}"),
                offset + cur,
                data.len() - cur,
            );
            break;
        }
        let name = frame_type_name(typ);
        let fr = tree.add_section(parent, format!("HTTP2 {name}"), offset + cur, 9 + len);
        tree.add_child(fr, "Length", format!("{len}"), offset + cur, 3);
        tree.add_child(fr, "Type", format!("{typ} ({name})"), offset + cur + 3, 1);
        tree.add_child(fr, "Flags", format!("{fl:#04x}"), offset + cur + 4, 1);
        tree.add_child(fr, "Stream", format!("{stream}"), offset + cur + 5, 4);
        infos.push(format!("{name} sid={stream}"));

        let payload = &data[cur + 9..frame_end];
        if typ == 0x01 {
            // HEADERS — try HPACK
            let hdr_start = if fl & 0x20 != 0 && payload.len() >= 5 {
                5 // skip priority
            } else {
                0
            };
            if hdr_start < payload.len() {
                match decoder.decode(&payload[hdr_start..]) {
                    Ok(headers) => {
                        for (k, v) in headers {
                            let ks = String::from_utf8_lossy(&k);
                            let vs = String::from_utf8_lossy(&v);
                            tree.add_child(fr, ks.to_string(), vs.to_string(), offset + cur + 9, 0);
                        }
                    }
                    Err(_) => {
                        tree.add_child(
                            fr,
                            "HEADERS",
                            format!("{} bytes (HPACK incomplete)", payload.len()),
                            offset + cur + 9,
                            payload.len(),
                        );
                    }
                }
            }
        } else if typ == 0x00 {
            tree.add_child(
                fr,
                "DATA",
                format!("{} bytes", payload.len()),
                offset + cur + 9,
                payload.len(),
            );
        }

        cur = frame_end;
    }

    summary.info = if infos.is_empty() {
        "HTTP/2".into()
    } else {
        format!("HTTP/2 {}", infos.join(", "))
    };

    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}

fn frame_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "DATA",
        0x01 => "HEADERS",
        0x02 => "PRIORITY",
        0x03 => "RST_STREAM",
        0x04 => "SETTINGS",
        0x05 => "PUSH_PROMISE",
        0x06 => "PING",
        0x07 => "GOAWAY",
        0x08 => "WINDOW_UPDATE",
        0x09 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}
