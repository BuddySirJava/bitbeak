//! TLS record / handshake dissector.

use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsRecordType};

use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_tls<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.tls = true;
    summary.protocol = "TLS".into();
    let sec = tree.add_section(parent, "Transport Layer Security", offset, data.len());

    let mut infos = Vec::new();
    let mut rest = data;
    let mut off = offset;

    while !rest.is_empty() {
        match parse_tls_plaintext(rest) {
            Ok((remain, record)) => {
                let consumed = rest.len() - remain.len();
                let typ = match record.hdr.record_type {
                    TlsRecordType::ChangeCipherSpec => "ChangeCipherSpec",
                    TlsRecordType::Alert => "Alert",
                    TlsRecordType::Handshake => "Handshake",
                    TlsRecordType::ApplicationData => "Application Data",
                    TlsRecordType::Heartbeat => "Heartbeat",
                    _ => "Record",
                };
                let rec = tree.add_section(parent, format!("TLS Record ({typ})"), off, consumed);
                tree.add_child(
                    rec,
                    "Content Type",
                    format!("{:?}", record.hdr.record_type),
                    off,
                    1,
                );
                tree.add_child(
                    rec,
                    "Version",
                    format!("{:?}", record.hdr.version),
                    off + 1,
                    2,
                );
                tree.add_child(rec, "Length", format!("{}", record.hdr.len), off + 3, 2);

                for msg in &record.msg {
                    if let TlsMessage::Handshake(hs) = msg {
                        match hs {
                            TlsMessageHandshake::ClientHello(ch) => {
                                infos.push("ClientHello".into());
                                tree.add_child(rec, "Handshake", "ClientHello", off + 5, 0);
                                // SNI from extensions if present
                                if let Some(ext) = &ch.ext {
                                    if let Some(sni) = extract_sni(ext) {
                                        tree.add_child(rec, "SNI", &sni, off + 5, 0);
                                        infos.push(format!("SNI={sni}"));
                                    }
                                }
                            }
                            TlsMessageHandshake::ServerHello(_) => {
                                infos.push("ServerHello".into());
                                tree.add_child(rec, "Handshake", "ServerHello", off + 5, 0);
                            }
                            TlsMessageHandshake::Certificate(_) => {
                                infos.push("Certificate".into());
                                tree.add_child(rec, "Handshake", "Certificate", off + 5, 0);
                            }
                            other => {
                                let s = format!("{other:?}");
                                let short = s.split('(').next().unwrap_or("Handshake");
                                infos.push(short.to_string());
                                tree.add_child(rec, "Handshake", short, off + 5, 0);
                            }
                        }
                    } else if matches!(msg, TlsMessage::ApplicationData(_)) {
                        infos.push("AppData".into());
                    }
                }

                off += consumed;
                rest = remain;
            }
            Err(_) => {
                tree.add_child(
                    sec,
                    "Data",
                    format!("{} bytes", rest.len()),
                    off,
                    rest.len(),
                );
                if infos.is_empty() {
                    infos.push(format!("{} bytes", rest.len()));
                }
                break;
            }
        }
    }

    summary.info = if infos.is_empty() {
        "TLS".into()
    } else {
        format!("TLS {}", infos.join(", "))
    };

    LayerResult {
        payload: &[],
        payload_offset: offset + data.len(),
    }
}

fn extract_sni(ext: &[u8]) -> Option<String> {
    // Very small SNI walk: look for extension type 0x0000
    let mut i = 0;
    while i + 4 <= ext.len() {
        let typ = u16::from_be_bytes([ext[i], ext[i + 1]]);
        let len = u16::from_be_bytes([ext[i + 2], ext[i + 3]]) as usize;
        i += 4;
        if i + len > ext.len() {
            break;
        }
        if typ == 0 && len >= 5 {
            // list_len(2) type(1) name_len(2) name
            let name_len = u16::from_be_bytes([ext[i + 3], ext[i + 4]]) as usize;
            if i + 5 + name_len <= ext.len() {
                return Some(String::from_utf8_lossy(&ext[i + 5..i + 5 + name_len]).into_owned());
            }
        }
        i += len;
    }
    None
}
