//! Capture filter (tcpdump subset) — evaluated in-process.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use thiserror::Error;

use crate::dissect::packet::PacketRecord;

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("empty filter")]
    Empty,
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub enum CaptureFilter {
    True,
    Host(IpAddr),
    Net { addr: u32, mask: u32 },
    Port(u16),
    SrcHost(IpAddr),
    DstHost(IpAddr),
    SrcPort(u16),
    DstPort(u16),
    Proto(&'static str),
    And(Box<CaptureFilter>, Box<CaptureFilter>),
    Or(Box<CaptureFilter>, Box<CaptureFilter>),
    Not(Box<CaptureFilter>),
}

impl CaptureFilter {
    pub fn matches_raw(&self, data: &[u8]) -> bool {
        match self {
            Self::True => true,
            Self::Not(f) => !f.matches_raw(data),
            Self::And(a, b) => a.matches_raw(data) && b.matches_raw(data),
            Self::Or(a, b) => a.matches_raw(data) || b.matches_raw(data),
            Self::Proto(p) => match *p {
                "tcp" => has_ip_proto(data, 6),
                "udp" => has_ip_proto(data, 17),
                "icmp" => has_ip_proto(data, 1),
                "arp" => link_ethertype(data) == Some(0x0806),
                "ip" => has_ip_version(data, 4),
                "ip6" => has_ip_version(data, 6),
                _ => true,
            },
            Self::Port(p) => has_port(data, *p, None),
            Self::SrcPort(p) => has_port(data, *p, Some(true)),
            Self::DstPort(p) => has_port(data, *p, Some(false)),
            Self::Host(ip) => has_host(data, *ip, None),
            Self::SrcHost(ip) => has_host(data, *ip, Some(true)),
            Self::DstHost(ip) => has_host(data, *ip, Some(false)),
            Self::Net { addr, mask } => has_net(data, *addr, *mask),
        }
    }

    pub fn matches_packet(&self, pkt: &PacketRecord) -> bool {
        self.matches_raw(&pkt.data)
    }

    /// True when the filter is simple enough for classic kernel BPF (tcp/udp/port/host ipv4).
    pub fn is_kernel_simple(&self) -> bool {
        match self {
            Self::True => true,
            Self::Host(IpAddr::V4(_))
            | Self::SrcHost(IpAddr::V4(_))
            | Self::DstHost(IpAddr::V4(_))
            | Self::Port(_)
            | Self::SrcPort(_)
            | Self::DstPort(_)
            | Self::Proto("tcp")
            | Self::Proto("udp")
            | Self::Proto("icmp")
            | Self::Proto("ip") => true,
            Self::And(a, b) => a.is_kernel_simple() && b.is_kernel_simple(),
            Self::Or(a, b) => a.is_kernel_simple() && b.is_kernel_simple(),
            Self::Not(f) => f.is_kernel_simple(),
            _ => false,
        }
    }
}

pub fn parse_capture_filter(input: &str) -> Result<CaptureFilter, FilterError> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(CaptureFilter::True);
    }
    parse_or(s)
}

fn parse_or(s: &str) -> Result<CaptureFilter, FilterError> {
    let parts = split_top(s, " or ");
    if parts.len() == 1 {
        return parse_and(parts[0]);
    }
    let mut it = parts.into_iter();
    let mut acc = parse_and(it.next().unwrap())?;
    for p in it {
        acc = CaptureFilter::Or(Box::new(acc), Box::new(parse_and(p)?));
    }
    Ok(acc)
}

fn parse_and(s: &str) -> Result<CaptureFilter, FilterError> {
    let parts = split_top(s, " and ");
    if parts.len() == 1 {
        return parse_not(parts[0]);
    }
    let mut it = parts.into_iter();
    let mut acc = parse_not(it.next().unwrap())?;
    for p in it {
        acc = CaptureFilter::And(Box::new(acc), Box::new(parse_not(p)?));
    }
    Ok(acc)
}

fn parse_not(s: &str) -> Result<CaptureFilter, FilterError> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("not ") {
        return Ok(CaptureFilter::Not(Box::new(parse_not(rest)?)));
    }
    if s.starts_with('(') && s.ends_with(')') {
        return parse_or(&s[1..s.len() - 1]);
    }
    parse_atom(s)
}

fn parse_atom(s: &str) -> Result<CaptureFilter, FilterError> {
    let s = s.trim();
    match s {
        "tcp" => return Ok(CaptureFilter::Proto("tcp")),
        "udp" => return Ok(CaptureFilter::Proto("udp")),
        "icmp" => return Ok(CaptureFilter::Proto("icmp")),
        "arp" => return Ok(CaptureFilter::Proto("arp")),
        "ip" => return Ok(CaptureFilter::Proto("ip")),
        "ip6" => return Ok(CaptureFilter::Proto("ip6")),
        _ => {}
    }
    let parts: Vec<_> = s.split_whitespace().collect();
    match parts.as_slice() {
        ["host", h] => Ok(CaptureFilter::Host(
            IpAddr::from_str(h).map_err(|e| FilterError::Parse(e.to_string()))?,
        )),
        ["src", "host", h] => Ok(CaptureFilter::SrcHost(
            IpAddr::from_str(h).map_err(|e| FilterError::Parse(e.to_string()))?,
        )),
        ["dst", "host", h] => Ok(CaptureFilter::DstHost(
            IpAddr::from_str(h).map_err(|e| FilterError::Parse(e.to_string()))?,
        )),
        ["port", p] => Ok(CaptureFilter::Port(p.parse().map_err(
            |e: std::num::ParseIntError| FilterError::Parse(e.to_string()),
        )?)),
        ["src", "port", p] => Ok(CaptureFilter::SrcPort(
            p.parse()
                .map_err(|e: std::num::ParseIntError| FilterError::Parse(e.to_string()))?,
        )),
        ["dst", "port", p] => Ok(CaptureFilter::DstPort(
            p.parse()
                .map_err(|e: std::num::ParseIntError| FilterError::Parse(e.to_string()))?,
        )),
        ["net", n] => parse_net(n),
        _ => Err(FilterError::Parse(format!("unknown atom: {s}"))),
    }
}

fn parse_net(n: &str) -> Result<CaptureFilter, FilterError> {
    if let Some((a, m)) = n.split_once('/') {
        let ip: Ipv4Addr = a
            .parse()
            .map_err(|e: std::net::AddrParseError| FilterError::Parse(e.to_string()))?;
        let prefix: u32 = m
            .parse()
            .map_err(|e: std::num::ParseIntError| FilterError::Parse(e.to_string()))?;
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix.min(32))
        };
        Ok(CaptureFilter::Net {
            addr: u32::from(ip) & mask,
            mask,
        })
    } else {
        let ip: Ipv4Addr = n
            .parse()
            .map_err(|e: std::net::AddrParseError| FilterError::Parse(e.to_string()))?;
        Ok(CaptureFilter::Net {
            addr: u32::from(ip),
            mask: 0xffff_ffff,
        })
    }
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

/// Locate L3 header: returns (ip_version, l3_offset).
fn l3_offset(data: &[u8]) -> Option<(u8, usize)> {
    // Ethernet II (+ optional 802.1Q)
    if data.len() >= 14 {
        let mut off = 14;
        let mut et = u16::from_be_bytes([data[12], data[13]]);
        if et == 0x8100 && data.len() >= 18 {
            et = u16::from_be_bytes([data[16], data[17]]);
            off = 18;
        }
        if et == 0x0800 {
            return Some((4, off));
        }
        if et == 0x86dd {
            return Some((6, off));
        }
        if et == 0x0806 {
            return None;
        }
    }
    // Linux cooked capture v1
    if data.len() >= 16 {
        let proto = u16::from_be_bytes([data[14], data[15]]);
        if proto == 0x0800 {
            return Some((4, 16));
        }
        if proto == 0x86dd {
            return Some((6, 16));
        }
    }
    // Linux cooked capture v2
    if data.len() >= 20 {
        let proto = u16::from_be_bytes([data[0], data[1]]);
        if proto == 0x0800 {
            return Some((4, 20));
        }
        if proto == 0x86dd {
            return Some((6, 20));
        }
    }
    // BSD DLT_NULL
    if data.len() >= 4 {
        let family = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match family {
            2 => return Some((4, 4)),
            10 | 28 | 30 => return Some((6, 4)),
            _ => {}
        }
    }
    None
}

fn link_ethertype(data: &[u8]) -> Option<u16> {
    if data.len() >= 14 {
        let mut et = u16::from_be_bytes([data[12], data[13]]);
        if et == 0x8100 && data.len() >= 18 {
            et = u16::from_be_bytes([data[16], data[17]]);
        }
        return Some(et);
    }
    if data.len() >= 16 {
        return Some(u16::from_be_bytes([data[14], data[15]]));
    }
    None
}

fn has_ip_version(data: &[u8], ver: u8) -> bool {
    l3_offset(data).is_some_and(|(v, _)| v == ver)
}

fn has_ip_proto(data: &[u8], proto: u8) -> bool {
    let Some((ver, off)) = l3_offset(data) else {
        return false;
    };
    match ver {
        4 => data.len() > off + 9 && data[off + 9] == proto,
        6 => data.len() > off + 6 && data[off + 6] == proto,
        _ => false,
    }
}

fn ipv6_addr_eq(data: &[u8], off: usize, ip: Ipv6Addr) -> bool {
    if data.len() < off + 16 {
        return false;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&data[off..off + 16]);
    Ipv6Addr::from(octets) == ip
}

fn has_host(data: &[u8], ip: IpAddr, dir: Option<bool>) -> bool {
    let Some((ver, off)) = l3_offset(data) else {
        return false;
    };
    match (ver, ip) {
        (4, IpAddr::V4(v4)) => {
            if data.len() < off + 20 {
                return false;
            }
            let src = Ipv4Addr::new(
                data[off + 12],
                data[off + 13],
                data[off + 14],
                data[off + 15],
            );
            let dst = Ipv4Addr::new(
                data[off + 16],
                data[off + 17],
                data[off + 18],
                data[off + 19],
            );
            match dir {
                Some(true) => src == v4,
                Some(false) => dst == v4,
                None => src == v4 || dst == v4,
            }
        }
        (6, IpAddr::V6(v6)) => {
            if data.len() < off + 40 {
                return false;
            }
            let src_ok = ipv6_addr_eq(data, off + 8, v6);
            let dst_ok = ipv6_addr_eq(data, off + 24, v6);
            match dir {
                Some(true) => src_ok,
                Some(false) => dst_ok,
                None => src_ok || dst_ok,
            }
        }
        _ => false,
    }
}

fn has_net(data: &[u8], addr: u32, mask: u32) -> bool {
    let Some((ver, off)) = l3_offset(data) else {
        return false;
    };
    if ver != 4 || data.len() < off + 20 {
        return false;
    }
    let src = u32::from_be_bytes([
        data[off + 12],
        data[off + 13],
        data[off + 14],
        data[off + 15],
    ]);
    let dst = u32::from_be_bytes([
        data[off + 16],
        data[off + 17],
        data[off + 18],
        data[off + 19],
    ]);
    (src & mask) == addr || (dst & mask) == addr
}

fn l4_offset(data: &[u8]) -> Option<(u8, usize, u8)> {
    let (ver, off) = l3_offset(data)?;
    match ver {
        4 => {
            if data.len() < off + 20 {
                return None;
            }
            let ihl = (data[off] & 0x0f) as usize * 4;
            let proto = data[off + 9];
            Some((ver, off + ihl, proto))
        }
        6 => {
            if data.len() < off + 40 {
                return None;
            }
            let proto = data[off + 6];
            Some((ver, off + 40, proto))
        }
        _ => None,
    }
}

fn has_port(data: &[u8], port: u16, dir: Option<bool>) -> bool {
    let Some((_ver, l4, proto)) = l4_offset(data) else {
        return false;
    };
    if proto != 6 && proto != 17 {
        return false;
    }
    if data.len() < l4 + 4 {
        return false;
    }
    let sp = u16::from_be_bytes([data[l4], data[l4 + 1]]);
    let dp = u16::from_be_bytes([data[l4 + 2], data[l4 + 3]]);
    match dir {
        Some(true) => sp == port,
        Some(false) => dp == port,
        None => sp == port || dp == port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn eth_ipv6_frame(src: Ipv6Addr, dst: Ipv6Addr, proto: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 14 + 40];
        pkt[12] = 0x86;
        pkt[13] = 0xdd;
        pkt[14] = 0x60; // v6
        pkt[14 + 6] = proto;
        pkt[14 + 8..14 + 24].copy_from_slice(&src.octets());
        pkt[14 + 24..14 + 40].copy_from_slice(&dst.octets());
        pkt
    }

    fn sll_ipv6_frame(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 16 + 40];
        pkt[14] = 0x86;
        pkt[15] = 0xdd;
        pkt[16] = 0x60;
        pkt[16 + 6] = 17;
        pkt[16 + 8..16 + 24].copy_from_slice(&src.octets());
        pkt[16 + 24..16 + 40].copy_from_slice(&dst.octets());
        pkt
    }

    #[test]
    fn parses_port_and_host() {
        let f = parse_capture_filter("tcp and port 80").unwrap();
        assert!(matches!(f, CaptureFilter::And(_, _)));
        let f = parse_capture_filter("host 10.0.0.1").unwrap();
        assert!(matches!(f, CaptureFilter::Host(_)));
    }

    #[test]
    fn ipv6_host_filter_ethernet() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let pkt = eth_ipv6_frame(src, dst, 17);
        let f = parse_capture_filter("host 2001:db8::1").unwrap();
        assert!(f.matches_raw(&pkt));
        let f = parse_capture_filter("dst host 2001:db8::2").unwrap();
        assert!(f.matches_raw(&pkt));
        let f = parse_capture_filter("host 2001:db8::3").unwrap();
        assert!(!f.matches_raw(&pkt));
    }

    #[test]
    fn ipv6_host_filter_sll() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        let dst = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x2);
        let pkt = sll_ipv6_frame(src, dst);
        let f = parse_capture_filter("host fe80::1").unwrap();
        assert!(f.matches_raw(&pkt));
    }
}
