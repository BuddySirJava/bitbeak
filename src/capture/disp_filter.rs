//! Display filter (Wireshark-ish subset).

use regex::Regex;
use thiserror::Error;

use crate::dissect::expert::ExpertSeverity;
use crate::dissect::packet::{FieldSlice, PacketRecord};

#[derive(Debug, Error)]
pub enum DispFilterError {
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub enum DisplayFilter {
    True,
    Proto(&'static str),
    IpAddr(String),
    TcpPort(u16),
    UdpPort(u16),
    FieldEq {
        field: String,
        slice: Option<FieldSlice>,
        val: String,
    },
    FieldContains {
        field: String,
        slice: Option<FieldSlice>,
        val: String,
    },
    FieldMatches {
        field: String,
        re: Regex,
    },
    FrameLen {
        op: Cmp,
        val: usize,
    },
    ExpertSeverity(ExpertSeverity),
    And(Box<DisplayFilter>, Box<DisplayFilter>),
    Or(Box<DisplayFilter>, Box<DisplayFilter>),
    Not(Box<DisplayFilter>),
}

#[derive(Debug, Clone, Copy)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl DisplayFilter {
    pub fn matches(&self, pkt: &PacketRecord) -> bool {
        match self {
            Self::True => true,
            Self::Not(f) => !f.matches(pkt),
            Self::And(a, b) => a.matches(pkt) && b.matches(pkt),
            Self::Or(a, b) => a.matches(pkt) || b.matches(pkt),
            Self::Proto(p) => match *p {
                "http" => pkt.flags.http,
                "http2" => pkt.flags.http2,
                "dns" => pkt.flags.dns,
                "mdns" => pkt.flags.mdns,
                "llmnr" => pkt.flags.llmnr,
                "dhcp" => pkt.flags.dhcp,
                "tcp" => pkt.flags.tcp,
                "udp" => pkt.flags.udp,
                "tls" => pkt.flags.tls,
                "websocket" => pkt.flags.websocket,
                "arp" => pkt.flags.arp,
                "icmp" => pkt.flags.icmp,
                "ip" => pkt.flags.ipv4,
                "ipv6" => pkt.flags.ipv6,
                "sip" => pkt.flags.sip,
                "rtp" => pkt.flags.rtp,
                "quic" => pkt.flags.quic_looking,
                "wifi" | "wlan" | "802.11" => {
                    pkt.flags.wifi
                        || pkt.summary.protocol.eq_ignore_ascii_case("802.11")
                        || pkt.summary.protocol.eq_ignore_ascii_case("WiFi")
                        || pkt.summary.protocol.contains("802.11")
                }
                _ => pkt.summary.protocol.eq_ignore_ascii_case(p),
            },
            Self::IpAddr(a) => pkt.summary.src.contains(a) || pkt.summary.dst.contains(a),
            Self::TcpPort(p) => {
                pkt.flags.tcp
                    && (pkt.summary.src.ends_with(&format!(":{p}"))
                        || pkt.summary.dst.ends_with(&format!(":{p}")))
            }
            Self::UdpPort(p) => {
                pkt.flags.udp
                    && (pkt.summary.src.ends_with(&format!(":{p}"))
                        || pkt.summary.dst.ends_with(&format!(":{p}")))
            }
            Self::FieldEq { field, slice, val } => pkt
                .field_sliced(field, *slice)
                .is_some_and(|v| v.eq_ignore_ascii_case(val.as_str())),
            Self::FieldContains { field, slice, val } => pkt
                .field_sliced(field, *slice)
                .is_some_and(|v| v.contains(val.as_str())),
            Self::FieldMatches { field, re } => {
                pkt.field(field).is_some_and(|v| re.is_match(v.as_str()))
            }
            Self::FrameLen { op, val } => {
                let n = pkt.data.len();
                match op {
                    Cmp::Eq => n == *val,
                    Cmp::Ne => n != *val,
                    Cmp::Lt => n < *val,
                    Cmp::Gt => n > *val,
                    Cmp::Le => n <= *val,
                    Cmp::Ge => n >= *val,
                }
            }
            Self::ExpertSeverity(sev) => pkt.expert.iter().any(|e| e.severity >= *sev),
        }
    }
}

pub fn parse_display_filter(input: &str) -> Result<DisplayFilter, DispFilterError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(DisplayFilter::True);
    }
    parse_or(s)
}

fn parse_or(s: &str) -> Result<DisplayFilter, DispFilterError> {
    let parts = split_top(s, " or ");
    let mut it = parts.into_iter();
    let mut acc = parse_and(it.next().unwrap())?;
    for p in it {
        acc = DisplayFilter::Or(Box::new(acc), Box::new(parse_and(p)?));
    }
    Ok(acc)
}

fn parse_and(s: &str) -> Result<DisplayFilter, DispFilterError> {
    let parts = split_top(s, " and ");
    let mut it = parts.into_iter();
    let mut acc = parse_not(it.next().unwrap())?;
    for p in it {
        acc = DisplayFilter::And(Box::new(acc), Box::new(parse_not(p)?));
    }
    Ok(acc)
}

fn parse_not(s: &str) -> Result<DisplayFilter, DispFilterError> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("not ") {
        return Ok(DisplayFilter::Not(Box::new(parse_not(rest)?)));
    }
    if s.starts_with('(') && s.ends_with(')') {
        return parse_or(&s[1..s.len() - 1]);
    }
    parse_atom(s)
}

fn parse_atom(s: &str) -> Result<DisplayFilter, DispFilterError> {
    let s = s.trim();
    for p in [
        "http2",
        "http",
        "dns",
        "mdns",
        "llmnr",
        "dhcp",
        "tcp",
        "udp",
        "tls",
        "websocket",
        "sip",
        "rtp",
        "quic",
        "wifi",
        "wlan",
        "802.11",
        "arp",
        "icmp",
        "ipv6",
        "ip",
    ] {
        if s.eq_ignore_ascii_case(p) {
            return Ok(DisplayFilter::Proto(p));
        }
    }
    if let Some(rest) = s.strip_prefix("ip.addr") {
        return parse_eq_str(rest, |v| DisplayFilter::IpAddr(v.to_string()));
    }
    if let Some(rest) = s.strip_prefix("ipv6.addr") {
        return parse_eq_str(rest, |v| DisplayFilter::IpAddr(v.to_string()));
    }
    if let Some(rest) = s.strip_prefix("tcp.port") {
        return parse_eq_u16(rest, DisplayFilter::TcpPort);
    }
    if let Some(rest) = s.strip_prefix("udp.port") {
        return parse_eq_u16(rest, DisplayFilter::UdpPort);
    }
    if let Some((field_raw, op, val)) = parse_field_op(s) {
        let (field, slice) = parse_field_ref(field_raw)?;
        return match op {
            "contains" => Ok(DisplayFilter::FieldContains {
                field,
                slice,
                val: unquote(val),
            }),
            "matches" => {
                let re =
                    Regex::new(val).map_err(|e| DispFilterError::Parse(format!("regex: {e}")))?;
                Ok(DisplayFilter::FieldMatches { field, re })
            }
            _ => Ok(DisplayFilter::FieldEq {
                field,
                slice,
                val: unquote(val),
            }),
        };
    }
    if let Some(rest) = s.strip_prefix("frame.len") {
        return parse_cmp_usize(rest, |op, val| DisplayFilter::FrameLen { op, val });
    }
    if let Some(rest) = s.strip_prefix("expert.severity") {
        let v = rest
            .trim()
            .trim_start_matches("==")
            .trim_start_matches('=')
            .trim();
        let sev = match v.to_ascii_lowercase().as_str() {
            "error" => ExpertSeverity::Error,
            "warn" | "warning" => ExpertSeverity::Warn,
            "note" => ExpertSeverity::Note,
            "comment" => ExpertSeverity::Comment,
            _ => {
                return Err(DispFilterError::Parse(format!(
                    "unknown expert.severity {v}"
                )))
            }
        };
        return Ok(DisplayFilter::ExpertSeverity(sev));
    }
    Err(DispFilterError::Parse(format!("unknown: {s}")))
}

fn parse_field_op(s: &str) -> Option<(&str, &str, &str)> {
    if let Some(idx) = s.find(" contains ") {
        let field = s[..idx].trim();
        let val = s[idx + " contains ".len()..].trim();
        return Some((field, "contains", val));
    }
    if let Some(idx) = s.find(" matches ") {
        let field = s[..idx].trim();
        let val = s[idx + " matches ".len()..].trim();
        return Some((field, "matches", val));
    }
    if let Some(idx) = s.find("==") {
        let field = s[..idx].trim();
        let val = s[idx + 2..].trim();
        return Some((field, "==", val));
    }
    if let Some(idx) = s.find('=') {
        let field = s[..idx].trim();
        let val = s[idx + 1..].trim();
        return Some((field, "=", val));
    }
    None
}

fn parse_field_ref(raw: &str) -> Result<(String, Option<FieldSlice>), DispFilterError> {
    let raw = raw.trim();
    let Some(open) = raw.find('[') else {
        return Ok((raw.to_string(), None));
    };
    if !raw.ends_with(']') {
        return Err(DispFilterError::Parse(format!("bad field slice: {raw}")));
    }
    let base = raw[..open].trim();
    if base.is_empty() {
        return Err(DispFilterError::Parse(format!("bad field slice: {raw}")));
    }
    let inner = raw[open + 1..raw.len() - 1].trim();
    let slice = if let Some(colon) = inner.find(':') {
        let start: usize = inner[..colon]
            .trim()
            .parse()
            .map_err(|e: std::num::ParseIntError| DispFilterError::Parse(e.to_string()))?;
        let end: usize = inner[colon + 1..]
            .trim()
            .parse()
            .map_err(|e: std::num::ParseIntError| DispFilterError::Parse(e.to_string()))?;
        FieldSlice::Range(start, end)
    } else {
        let idx: usize = inner
            .parse()
            .map_err(|e: std::num::ParseIntError| DispFilterError::Parse(e.to_string()))?;
        FieldSlice::Index(idx)
    };
    Ok((base.to_string(), Some(slice)))
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn parse_eq_str(
    rest: &str,
    f: impl FnOnce(&str) -> DisplayFilter,
) -> Result<DisplayFilter, DispFilterError> {
    let v = rest
        .trim()
        .trim_start_matches("==")
        .trim_start_matches('=')
        .trim()
        .trim_matches('"');
    if v.is_empty() {
        return Err(DispFilterError::Parse("missing value".into()));
    }
    Ok(f(v))
}

fn parse_eq_u16(
    rest: &str,
    f: impl FnOnce(u16) -> DisplayFilter,
) -> Result<DisplayFilter, DispFilterError> {
    let v = rest
        .trim()
        .trim_start_matches("==")
        .trim_start_matches('=')
        .trim();
    let n: u16 = v
        .parse()
        .map_err(|e: std::num::ParseIntError| DispFilterError::Parse(e.to_string()))?;
    Ok(f(n))
}

fn parse_cmp_usize(
    rest: &str,
    f: impl FnOnce(Cmp, usize) -> DisplayFilter,
) -> Result<DisplayFilter, DispFilterError> {
    let rest = rest.trim();
    let (op, val_s) = if let Some(v) = rest.strip_prefix("==") {
        (Cmp::Eq, v)
    } else if let Some(v) = rest.strip_prefix("!=") {
        (Cmp::Ne, v)
    } else if let Some(v) = rest.strip_prefix("<=") {
        (Cmp::Le, v)
    } else if let Some(v) = rest.strip_prefix(">=") {
        (Cmp::Ge, v)
    } else if let Some(v) = rest.strip_prefix('<') {
        (Cmp::Lt, v)
    } else if let Some(v) = rest.strip_prefix('>') {
        (Cmp::Gt, v)
    } else if let Some(v) = rest.strip_prefix('=') {
        (Cmp::Eq, v)
    } else {
        return Err(DispFilterError::Parse(format!("bad cmp: {rest}")));
    };
    let val: usize = val_s
        .trim()
        .parse()
        .map_err(|e: std::num::ParseIntError| DispFilterError::Parse(e.to_string()))?;
    Ok(f(op, val))
}

fn split_top<'a>(s: &'a str, sep: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    let bytes = s.as_bytes();
    let sep_b = sep.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && i + sep_b.len() <= bytes.len() && &bytes[i..i + sep_b.len()] == sep_b {
            out.push(s[start..i].trim());
            i += sep_b.len();
            start = i;
            continue;
        }
        i += 1;
    }
    out.push(s[start..].trim());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::packet::{LinkType, PacketSummary, ProtocolFlags};
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::time::{Instant, SystemTime};

    fn pkt_http() -> PacketRecord {
        let mut fields = HashMap::new();
        fields.insert("http.request.method".into(), "GET".into());
        fields.insert("frame.protocols".into(), "eth:ip:tcp:http".into());
        PacketRecord {
            id: 1,
            at: Instant::now(),
            wall: SystemTime::now(),
            interface: "eth0".into(),
            link_type: LinkType::Ethernet,
            orig_len: 100,
            data: Bytes::from_static(&[0u8; 100]),
            summary: PacketSummary {
                src: "10.0.0.1:1234".into(),
                dst: "10.0.0.2:80".into(),
                protocol: "HTTP".into(),
                info: "GET /".into(),
                len: 100,
            },
            flags: ProtocolFlags {
                http: true,
                tcp: true,
                ipv4: true,
                ..Default::default()
            },
            expert: Vec::new(),
            tree: None,
            decrypted: None,
            fields,
        }
    }

    #[test]
    fn display_http_and_port() {
        let f = parse_display_filter("http and tcp.port == 80").unwrap();
        assert!(f.matches(&pkt_http()));
        let f2 = parse_display_filter("dns").unwrap();
        assert!(!f2.matches(&pkt_http()));
    }

    #[test]
    fn display_field_contains() {
        let f = parse_display_filter(r#"http.request.method contains "GE""#).unwrap();
        assert!(f.matches(&pkt_http()));
    }

    fn pkt_sip_udp() -> PacketRecord {
        PacketRecord {
            id: 2,
            at: Instant::now(),
            wall: SystemTime::now(),
            interface: "eth0".into(),
            link_type: LinkType::Ethernet,
            orig_len: 200,
            data: Bytes::from_static(&[0u8; 200]),
            summary: PacketSummary {
                src: "10.0.0.1:5060".into(),
                dst: "10.0.0.2:5060".into(),
                protocol: "SIP".into(),
                info: "INVITE sip:a@b SIP/2.0".into(),
                len: 200,
            },
            flags: ProtocolFlags {
                sip: true,
                udp: true,
                ipv4: true,
                ..Default::default()
            },
            expert: Vec::new(),
            tree: None,
            decrypted: None,
            fields: HashMap::new(),
        }
    }

    #[test]
    fn display_sip_and_udp() {
        let f = parse_display_filter("sip and udp").unwrap();
        assert!(f.matches(&pkt_sip_udp()));
        let f2 = parse_display_filter("quic").unwrap();
        assert!(!f2.matches(&pkt_sip_udp()));
    }

    #[test]
    fn display_field_slice_eq() {
        let f = parse_display_filter(r#"http.request.method[0:2] == "GE""#).unwrap();
        assert!(f.matches(&pkt_http()));
        let f2 = parse_display_filter(r#"http.request.method[0:2] == "PO""#).unwrap();
        assert!(!f2.matches(&pkt_http()));
    }

    #[test]
    fn display_ip_src_alias() {
        let f = parse_display_filter("ip.src == 10.0.0.1").unwrap();
        assert!(f.matches(&pkt_http()));
        let f2 = parse_display_filter("ip.dst == 10.0.0.2").unwrap();
        assert!(f2.matches(&pkt_http()));
    }
}
