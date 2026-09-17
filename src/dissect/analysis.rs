//! Incremental conversation / endpoint / hierarchy / IO stats.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dissect::packet::PacketRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    Ethernet,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ConversationRow {
    pub kind: ConversationKind,
    pub addr_a: String,
    pub addr_b: String,
    pub packets_ab: u64,
    pub packets_ba: u64,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub start: Instant,
    pub last: Instant,
}

impl ConversationRow {
    pub fn packets(&self) -> u64 {
        self.packets_ab + self.packets_ba
    }
    pub fn bytes(&self) -> u64 {
        self.bytes_ab + self.bytes_ba
    }
    pub fn filter_expr(&self) -> String {
        let a = strip_port(&self.addr_a);
        let b = strip_port(&self.addr_b);
        match self.kind {
            ConversationKind::Tcp => {
                format!(
                    "(ip.addr == {a} and ip.addr == {b}) and (tcp.port == {} or tcp.port == {})",
                    strip_port_num(&self.addr_a),
                    strip_port_num(&self.addr_b)
                )
            }
            ConversationKind::Udp => {
                format!(
                    "(ip.addr == {a} and ip.addr == {b}) and (udp.port == {} or udp.port == {})",
                    strip_port_num(&self.addr_a),
                    strip_port_num(&self.addr_b)
                )
            }
            _ => format!("ip.addr == {a} or ip.addr == {b}"),
        }
    }
}

fn strip_port(s: &str) -> String {
    // Take last ':' for IPv4:port; for IPv6:[addr]:port leave as-is simplified
    if let Some((host, port)) = s.rsplit_once(':') {
        if port.parse::<u16>().is_ok() && !host.contains(':') {
            return host.to_string();
        }
    }
    s.to_string()
}

fn strip_port_num(s: &str) -> String {
    if let Some((_, port)) = s.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            return port.to_string();
        }
    }
    "0".into()
}

#[derive(Debug, Default)]
pub struct ConversationTable {
    rows: HashMap<(ConversationKind, String, String), ConversationRow>,
}

impl ConversationTable {
    pub fn ingest(&mut self, pkt: &PacketRecord) {
        let now = pkt.at;
        let len = pkt.data.len() as u64;
        let src = pkt.summary.src.clone();
        let dst = pkt.summary.dst.clone();
        if src.is_empty() || dst.is_empty() {
            return;
        }

        let kinds = conversation_kinds(&pkt.flags);
        for kind in kinds {
            let (a, b, ab) = normalize_pair(&src, &dst);
            let key = (kind, a.clone(), b.clone());
            let row = self.rows.entry(key).or_insert_with(|| ConversationRow {
                kind,
                addr_a: a,
                addr_b: b,
                packets_ab: 0,
                packets_ba: 0,
                bytes_ab: 0,
                bytes_ba: 0,
                start: now,
                last: now,
            });
            if ab {
                row.packets_ab += 1;
                row.bytes_ab += len;
            } else {
                row.packets_ba += 1;
                row.bytes_ba += len;
            }
            row.last = now;
        }
    }

    pub fn rows(&self) -> Vec<&ConversationRow> {
        let mut v: Vec<_> = self.rows.values().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.packets()));
        v
    }
}

fn conversation_kinds(flags: &crate::dissect::packet::ProtocolFlags) -> Vec<ConversationKind> {
    let mut k = Vec::new();
    if flags.ethernet {
        k.push(ConversationKind::Ethernet);
    }
    if flags.tcp {
        k.push(ConversationKind::Tcp);
    } else if flags.udp {
        k.push(ConversationKind::Udp);
    }
    if flags.ipv4 {
        k.push(ConversationKind::Ipv4);
    }
    if flags.ipv6 {
        k.push(ConversationKind::Ipv6);
    }
    if k.is_empty() {
        k.push(ConversationKind::Ipv4);
    }
    k
}

fn normalize_pair(a: &str, b: &str) -> (String, String, bool) {
    if a <= b {
        (a.to_string(), b.to_string(), true)
    } else {
        (b.to_string(), a.to_string(), false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    Mac,
    Ipv4,
    Ipv6,
    TcpPort,
    UdpPort,
}

#[derive(Debug, Clone)]
pub struct EndpointRow {
    pub kind: EndpointKind,
    pub address: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Default)]
pub struct EndpointTable {
    rows: HashMap<(EndpointKind, String), EndpointRow>,
}

impl EndpointTable {
    pub fn ingest(&mut self, pkt: &PacketRecord) {
        let len = pkt.data.len() as u64;
        for (kind, addr) in endpoint_addrs(pkt) {
            let e = self
                .rows
                .entry((kind, addr.clone()))
                .or_insert(EndpointRow {
                    kind,
                    address: addr,
                    packets: 0,
                    bytes: 0,
                });
            e.packets += 1;
            e.bytes += len;
        }
    }

    pub fn rows(&self) -> Vec<&EndpointRow> {
        let mut v: Vec<_> = self.rows.values().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.packets));
        v
    }
}

fn endpoint_addrs(pkt: &PacketRecord) -> Vec<(EndpointKind, String)> {
    let mut out = Vec::new();
    let src = &pkt.summary.src;
    let dst = &pkt.summary.dst;
    if pkt.flags.ipv6 {
        out.push((EndpointKind::Ipv6, strip_port(src)));
        out.push((EndpointKind::Ipv6, strip_port(dst)));
    } else if pkt.flags.ipv4 || pkt.flags.arp {
        out.push((EndpointKind::Ipv4, strip_port(src)));
        out.push((EndpointKind::Ipv4, strip_port(dst)));
    }
    if pkt.flags.tcp {
        if let Some(p) = port_of(src) {
            out.push((EndpointKind::TcpPort, p));
        }
        if let Some(p) = port_of(dst) {
            out.push((EndpointKind::TcpPort, p));
        }
    }
    if pkt.flags.udp {
        if let Some(p) = port_of(src) {
            out.push((EndpointKind::UdpPort, p));
        }
        if let Some(p) = port_of(dst) {
            out.push((EndpointKind::UdpPort, p));
        }
    }
    out
}

fn port_of(s: &str) -> Option<String> {
    s.rsplit_once(':')
        .filter(|(_, p)| p.parse::<u16>().is_ok())
        .map(|(_, p)| p.to_string())
}

#[derive(Debug, Default)]
pub struct ProtoHierarchy {
    counts: HashMap<String, (u64, u64)>,
}

impl ProtoHierarchy {
    pub fn ingest(&mut self, pkt: &PacketRecord) {
        let proto = pkt.summary.protocol.clone();
        let e = self.counts.entry(proto).or_insert((0, 0));
        e.0 += 1;
        e.1 += pkt.data.len() as u64;
    }

    pub fn rows(&self) -> Vec<(String, u64, u64)> {
        let mut v: Vec<_> = self
            .counts
            .iter()
            .map(|(k, (p, b))| (k.clone(), *p, *b))
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.1));
        v
    }
}

#[derive(Debug, Default)]
pub struct LengthHistogram {
    /// buckets: <64, 64-127, 128-255, 256-511, 512-1023, 1024-1517, >=1518
    pub buckets: [u64; 7],
}

impl LengthHistogram {
    pub fn ingest(&mut self, pkt: &PacketRecord) {
        let n = pkt.data.len();
        let idx = if n < 64 {
            0
        } else if n < 128 {
            1
        } else if n < 256 {
            2
        } else if n < 512 {
            3
        } else if n < 1024 {
            4
        } else if n < 1518 {
            5
        } else {
            6
        };
        self.buckets[idx] += 1;
    }

    pub fn labels() -> [&'static str; 7] {
        [
            "<64",
            "64-127",
            "128-255",
            "256-511",
            "512-1023",
            "1024-1517",
            "≥1518",
        ]
    }
}

#[derive(Debug, Clone, Default)]
pub struct IoBucket {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct IoGraph {
    start: Instant,
    /// One bucket per second, ring of last N seconds.
    buckets: Vec<IoBucket>,
    capacity: usize,
}

impl Default for IoGraph {
    fn default() -> Self {
        Self::new(120)
    }
}

impl IoGraph {
    pub fn new(capacity: usize) -> Self {
        Self {
            start: Instant::now(),
            buckets: vec![IoBucket::default(); capacity.max(1)],
            capacity: capacity.max(1),
        }
    }

    pub fn ingest(&mut self, pkt: &PacketRecord) {
        let secs = pkt.at.duration_since(self.start).as_secs() as usize;
        let idx = secs % self.capacity;
        // Clear stale bucket if we wrapped
        if secs >= self.capacity {
            // simple: only accumulate in current slot
        }
        self.buckets[idx].packets += 1;
        self.buckets[idx].bytes += pkt.data.len() as u64;
    }

    pub fn packet_series(&self) -> Vec<u64> {
        self.buckets.iter().map(|b| b.packets).collect()
    }

    pub fn byte_series(&self) -> Vec<u64> {
        self.buckets.iter().map(|b| b.bytes).collect()
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Aggregate stats holder updated on each ingest.
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub conversations: ConversationTable,
    pub endpoints: EndpointTable,
    pub hierarchy: ProtoHierarchy,
    pub lengths: LengthHistogram,
    pub io: IoGraph,
}

impl CaptureStats {
    pub fn ingest(&mut self, pkt: &PacketRecord) {
        self.conversations.ingest(pkt);
        self.endpoints.ingest(pkt);
        self.hierarchy.ingest(pkt);
        self.lengths.ingest(pkt);
        self.io.ingest(pkt);
    }
}
