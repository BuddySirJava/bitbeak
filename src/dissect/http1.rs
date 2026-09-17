//! HTTP/1.x dissector.

use crate::dissect::packet::{LayerResult, PacketSummary, ProtocolFlags};
use crate::dissect::tree::ProtoTree;

pub fn dissect_http1<'a>(
    tree: &mut ProtoTree,
    parent: usize,
    data: &'a [u8],
    offset: usize,
    flags: &mut ProtocolFlags,
    summary: &mut PacketSummary,
) -> LayerResult<'a> {
    flags.http = true;
    summary.protocol = "HTTP".into();
    let sec = tree.add_section(parent, "Hypertext Transfer Protocol", offset, data.len());

    let mut headers = [httparse::EMPTY_HEADER; 64];
    // Try request
    let mut req = httparse::Request::new(&mut headers);
    if let Ok(httparse::Status::Complete(n)) = req.parse(data) {
        let method = req.method.unwrap_or("?");
        let path = req.path.unwrap_or("/");
        tree.add_child(
            sec,
            "Request Line",
            format!("{method} {path}"),
            offset,
            n.min(data.len()),
        );
        for h in req.headers.iter() {
            let v = std::str::from_utf8(h.value).unwrap_or("?");
            tree.add_child(sec, h.name, v, offset, 0);
        }
        summary.info = format!("{method} {path}");
        let body = if n < data.len() { &data[n..] } else { &[] };
        if !body.is_empty() {
            tree.add_child(
                sec,
                "Body",
                format!("{} bytes", body.len()),
                offset + n,
                body.len(),
            );
        }
        return LayerResult {
            payload: body,
            payload_offset: offset + n,
        };
    }

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    if let Ok(httparse::Status::Complete(n)) = resp.parse(data) {
        let code = resp.code.unwrap_or(0);
        let reason = resp.reason.unwrap_or("");
        tree.add_child(
            sec,
            "Status Line",
            format!("HTTP {code} {reason}"),
            offset,
            n.min(data.len()),
        );
        for h in resp.headers.iter() {
            let v = std::str::from_utf8(h.value).unwrap_or("?");
            tree.add_child(sec, h.name, v, offset, 0);
        }
        summary.info = format!("HTTP {code} {reason}");
        let body = if n < data.len() { &data[n..] } else { &[] };
        if !body.is_empty() {
            tree.add_child(
                sec,
                "Body",
                format!("{} bytes", body.len()),
                offset + n,
                body.len(),
            );
        }
        return LayerResult {
            payload: body,
            payload_offset: offset + n,
        };
    }

    // Partial
    let preview = String::from_utf8_lossy(&data[..data.len().min(80)]);
    tree.add_child(sec, "Data", preview.trim().to_string(), offset, data.len());
    summary.info = "HTTP (partial)".into();
    LayerResult {
        payload: data,
        payload_offset: offset,
    }
}
