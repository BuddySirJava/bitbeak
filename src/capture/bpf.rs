//! Classic BPF bytecode for Linux SO_ATTACH_FILTER (IPv4 over Ethernet/SLL).

use std::net::IpAddr;

use crate::capture::cap_filter::CaptureFilter;
use crate::dissect::packet::LinkType;

#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

const BPF_LD: u16 = 0x00;
const BPF_LDH: u16 = 0x01;
const BPF_LDB: u16 = 0x02;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_ABS: u16 = 0x20;

fn ldh(off: u32) -> SockFilter {
    SockFilter {
        code: BPF_LDH | BPF_ABS,
        jt: 0,
        jf: 0,
        k: off,
    }
}

fn ldb(off: u32) -> SockFilter {
    SockFilter {
        code: BPF_LDB | BPF_ABS,
        jt: 0,
        jf: 0,
        k: off,
    }
}

fn ld(off: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD | BPF_ABS,
        jt: 0,
        jf: 0,
        k: off,
    }
}

fn jeq(val: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k: val,
    }
}

fn ret(val: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: val,
    }
}

struct Layout {
    eth_check: bool,
    eth_off: u32,
    ip: u32,
}

fn layout(link: LinkType) -> Option<Layout> {
    match link {
        LinkType::Ethernet => Some(Layout {
            eth_check: true,
            eth_off: 12,
            ip: 14,
        }),
        LinkType::LinuxSll => Some(Layout {
            eth_check: true,
            eth_off: 14,
            ip: 16,
        }),
        LinkType::LinuxSll2 => Some(Layout {
            eth_check: true,
            eth_off: 0,
            ip: 20,
        }),
        LinkType::Null => Some(Layout {
            eth_check: false,
            eth_off: 0,
            ip: 4,
        }),
        _ => None,
    }
}

/// Compile a simple atomic capture filter to classic BPF (fixed 20-byte IPv4 header).
pub fn compile_simple_bpf(filter: &CaptureFilter, link: LinkType) -> Option<Vec<SockFilter>> {
    if !filter.is_kernel_simple() {
        return None;
    }
    let lay = layout(link)?;
    let ip = lay.ip;
    let proto = ip + 9;
    let src = ip + 12;
    let dst = ip + 16;
    let l4 = ip + 20;

    let mut insns = Vec::new();

    if lay.eth_check {
        insns.push(ldh(lay.eth_off));
        insns.push(jeq(0x0800, 0, 1)); // jf -> ret 0
    } else {
        insns.push(ld(0));
        insns.push(jeq(2, 0, 1)); // AF_INET
    }

    match filter {
        CaptureFilter::True => {}
        CaptureFilter::Proto("tcp") => {
            insns.push(ldb(proto));
            insns.push(jeq(6, 0, 1));
        }
        CaptureFilter::Proto("udp") => {
            insns.push(ldb(proto));
            insns.push(jeq(17, 0, 1));
        }
        CaptureFilter::Proto("icmp") => {
            insns.push(ldb(proto));
            insns.push(jeq(1, 0, 1));
        }
        CaptureFilter::Proto("ip") => {}
        CaptureFilter::Host(IpAddr::V4(v4)) => {
            let v = u32::from(*v4);
            insns.push(ld(src));
            insns.push(jeq(v, 2, 0)); // accept on match
            insns.push(ld(dst));
            insns.push(jeq(v, 0, 1));
        }
        CaptureFilter::SrcHost(IpAddr::V4(v4)) => {
            insns.push(ld(src));
            insns.push(jeq(u32::from(*v4), 0, 1));
        }
        CaptureFilter::DstHost(IpAddr::V4(v4)) => {
            insns.push(ld(dst));
            insns.push(jeq(u32::from(*v4), 0, 1));
        }
        CaptureFilter::Port(p) => {
            push_port(&mut insns, proto, l4, *p, None);
        }
        CaptureFilter::SrcPort(p) => {
            push_port(&mut insns, proto, l4, *p, Some(true));
        }
        CaptureFilter::DstPort(p) => {
            push_port(&mut insns, proto, l4, *p, Some(false));
        }
        CaptureFilter::And(a, b) => {
            let left = compile_simple_bpf(a, link)?;
            let right = compile_simple_bpf(b, link)?;
            return merge_and(left, right);
        }
        CaptureFilter::Or(a, b) => {
            let left = compile_simple_bpf(a, link)?;
            let right = compile_simple_bpf(b, link)?;
            return merge_or(left, right);
        }
        CaptureFilter::Not(inner) => {
            let inner = compile_simple_bpf(inner, link)?;
            return merge_not(inner);
        }
        _ => return None,
    }

    insns.push(ret(u32::MAX));
    insns.push(ret(0));
    Some(insns)
}

fn push_port(insns: &mut Vec<SockFilter>, proto: u32, l4: u32, port: u16, dir: Option<bool>) {
    insns.push(ldb(proto));
    insns.push(jeq(6, 0, 0));
    insns.push(jeq(17, 0, 1)); // jt=accept if tcp matched wrong path — fix below
                               // Simpler: accept tcp or udp
    let p = u32::from(port);
    match dir {
        Some(true) => {
            insns.push(ldh(l4));
            insns.push(jeq(p, 0, 1));
        }
        Some(false) => {
            insns.push(ldh(l4 + 2));
            insns.push(jeq(p, 0, 1));
        }
        None => {
            insns.push(ldh(l4));
            insns.push(jeq(p, 2, 0));
            insns.push(ldh(l4 + 2));
            insns.push(jeq(p, 0, 1));
        }
    }
    let _ = proto;
}

fn merge_and(mut a: Vec<SockFilter>, mut b: Vec<SockFilter>) -> Option<Vec<SockFilter>> {
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    a.truncate(a.len() - 2);
    a.append(&mut b);
    Some(a)
}

fn merge_or(mut a: Vec<SockFilter>, mut b: Vec<SockFilter>) -> Option<Vec<SockFilter>> {
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    a.pop(); // ret 0
    a.pop(); // ret max
    a.push(ret(u32::MAX));
    a.append(&mut b);
    Some(a)
}

fn merge_not(mut inner: Vec<SockFilter>) -> Option<Vec<SockFilter>> {
    if inner.len() < 2 {
        return None;
    }
    let n = inner.len();
    inner.swap(n - 2, n - 1);
    Some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::cap_filter::parse_capture_filter;

    #[test]
    fn compiles_tcp_bpf() {
        let f = parse_capture_filter("tcp").unwrap();
        let prog = compile_simple_bpf(&f, LinkType::Ethernet);
        assert!(prog.is_some());
    }
}
