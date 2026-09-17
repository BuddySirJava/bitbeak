//! Packet record, store, and summary types.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;

use crate::dissect::expert::ExpertInfo;
use crate::dissect::tree::ProtoTree;

/// Link-layer type (pcap DLT subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum LinkType {
    Null = 0,
    Ethernet = 1,
    Ieee80211 = 105,
    Ieee80211Radio = 127,
    Raw = 12,
    LinuxSll = 113,
    LinuxSll2 = 276,
    Unknown(u32),
}

impl LinkType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Ethernet,
            12 => Self::Raw,
            105 => Self::Ieee80211,
            127 => Self::Ieee80211Radio,
            113 => Self::LinuxSll,
            276 => Self::LinuxSll2,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Ethernet => 1,
            Self::Raw => 12,
            Self::Ieee80211 => 105,
            Self::Ieee80211Radio => 127,
            Self::LinuxSll => 113,
            Self::LinuxSll2 => 276,
            Self::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PacketSummary {
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub info: String,
    pub len: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ProtocolFlags {
    pub ethernet: bool,
    pub vlan: bool,
    pub arp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub icmp: bool,
    pub icmpv6: bool,
    pub tcp: bool,
    pub udp: bool,
    pub dns: bool,
    pub mdns: bool,
    pub llmnr: bool,
    pub dhcp: bool,
    pub http: bool,
    pub http2: bool,
    pub tls: bool,
    pub websocket: bool,
    pub quic_looking: bool,
    pub wifi: bool,
    pub sip: bool,
    pub rtp: bool,
}

impl ProtocolFlags {
    pub fn any(&self) -> bool {
        self.ethernet
            || self.arp
            || self.ipv4
            || self.ipv6
            || self.icmp
            || self.icmpv6
            || self.tcp
            || self.udp
            || self.dns
            || self.http
            || self.tls
    }

    pub fn protocol_name(&self) -> &'static str {
        if self.websocket {
            "WebSocket"
        } else if self.http2 {
            "HTTP2"
        } else if self.http {
            "HTTP"
        } else if self.tls {
            "TLS"
        } else if self.dhcp {
            "DHCP"
        } else if self.mdns {
            "MDNS"
        } else if self.llmnr {
            "LLMNR"
        } else if self.dns {
            "DNS"
        } else if self.quic_looking {
            "QUIC"
        } else if self.tcp {
            "TCP"
        } else if self.udp {
            "UDP"
        } else if self.icmp {
            "ICMP"
        } else if self.icmpv6 {
            "ICMPv6"
        } else if self.arp {
            "ARP"
        } else if self.ipv6 {
            "IPv6"
        } else if self.ipv4 {
            "IPv4"
        } else if self.ethernet {
            "Ethernet"
        } else {
            "Data"
        }
    }
}

/// Wireshark-style display filter fields extracted during dissection.
pub type DisplayFields = HashMap<String, String>;

/// Fully dissected view of one packet (not necessarily stored).
#[derive(Debug, Clone)]
pub struct DissectedPacket {
    pub tree: ProtoTree,
    pub summary: PacketSummary,
    pub flags: ProtocolFlags,
    pub expert: Vec<ExpertInfo>,
    pub payload_offset: usize,
    pub payload: Bytes,
    pub decrypted: Option<Bytes>,
    pub fields: DisplayFields,
}

/// Stored capture packet.
#[derive(Debug, Clone)]
pub struct PacketRecord {
    pub id: u64,
    pub at: Instant,
    pub wall: SystemTime,
    pub interface: String,
    pub link_type: LinkType,
    pub orig_len: u32,
    pub data: Bytes,
    pub summary: PacketSummary,
    pub flags: ProtocolFlags,
    pub expert: Vec<ExpertInfo>,
    pub tree: Option<ProtoTree>,
    pub decrypted: Option<Bytes>,
    pub fields: DisplayFields,
}

impl PacketRecord {
    pub fn field(&self, name: &str) -> Option<String> {
        for candidate in field_candidates(name) {
            if let Some(v) = self.fields.get(candidate) {
                return Some(v.clone());
            }
            if let Some(v) = field_heuristic(candidate, &self.flags, &self.summary) {
                return Some(v);
            }
            if let Some(v) = field_computed(candidate, &self.summary) {
                return Some(v);
            }
        }
        None
    }

    pub fn field_sliced(&self, name: &str, slice: Option<FieldSlice>) -> Option<String> {
        self.field(name).map(|v| apply_field_slice(&v, slice))
    }

    pub fn ensure_tree(&mut self) -> &ProtoTree {
        if self.tree.is_none() {
            let d = crate::dissect::dissect(&self.data, self.link_type, None);
            self.summary = d.summary;
            self.flags = d.flags;
            self.expert = d.expert;
            self.fields = d.fields;
            self.tree = Some(d.tree);
            if d.decrypted.is_some() {
                self.decrypted = d.decrypted;
            }
        }
        self.tree.as_ref().expect("tree just set")
    }
}

/// Byte or character slice for display-filter field references (`field[i:j]`, `field[i]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSlice {
    Index(usize),
    Range(usize, usize),
}

pub fn apply_field_slice(value: &str, slice: Option<FieldSlice>) -> String {
    let Some(slice) = slice else {
        return value.to_string();
    };
    let chars: Vec<char> = value.chars().collect();
    match slice {
        FieldSlice::Index(i) => chars.get(i).map(|c| c.to_string()).unwrap_or_default(),
        FieldSlice::Range(start, end) => {
            if start >= chars.len() || start >= end {
                String::new()
            } else {
                chars[start..end.min(chars.len())].iter().collect()
            }
        }
    }
}

fn field_candidates(name: &str) -> Vec<&str> {
    match name {
        "http.host" => vec!["http.request.host", "http.host", "Host"],
        "ip.src" | "ip.dst" | "tcp.srcport" | "tcp.dstport" | "udp.srcport" | "udp.dstport"
        | "udp.port" => vec![name],
        other => vec![other],
    }
}

fn field_heuristic(name: &str, flags: &ProtocolFlags, summary: &PacketSummary) -> Option<String> {
    match name {
        "http.request.method" if flags.http => {
            summary.info.split_whitespace().next().map(String::from)
        }
        "http.response.code" if flags.http && summary.info.starts_with("HTTP ") => {
            summary.info.split_whitespace().nth(1).map(String::from)
        }
        "dns.qry.name" if flags.dns => summary
            .info
            .strip_prefix("Standard query ")
            .map(String::from),
        "frame.protocols" => None,
        _ => None,
    }
}

fn field_computed(name: &str, summary: &PacketSummary) -> Option<String> {
    match name {
        "ip.src" => Some(strip_host_port(&summary.src)),
        "ip.dst" => Some(strip_host_port(&summary.dst)),
        "tcp.srcport" | "udp.srcport" => endpoint_port(&summary.src).map(|p| p.to_string()),
        "tcp.dstport" | "udp.dstport" => endpoint_port(&summary.dst).map(|p| p.to_string()),
        "udp.port" => endpoint_port(&summary.src)
            .or_else(|| endpoint_port(&summary.dst))
            .map(|p| p.to_string()),
        _ => None,
    }
}

fn strip_host_port(endpoint: &str) -> String {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .unwrap_or_else(|| endpoint.to_string())
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
}

/// Bounded ring of captured packets.
#[derive(Debug)]
pub struct PacketStore {
    packets: VecDeque<PacketRecord>,
    max: usize,
    next_id: u64,
    pub dropped: u64,
    start: Instant,
}

impl PacketStore {
    pub fn new(max: usize) -> Self {
        Self {
            packets: VecDeque::with_capacity(max.min(10_000)),
            max: max.max(1),
            next_id: 1,
            dropped: 0,
            start: Instant::now(),
        }
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.dropped = 0;
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn push(&mut self, mut rec: PacketRecord) -> u64 {
        if self.packets.len() >= self.max {
            self.packets.pop_front();
            self.dropped += 1;
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        rec.id = id;
        self.packets.push_back(rec);
        id
    }

    pub fn push_raw(
        &mut self,
        data: Bytes,
        link_type: LinkType,
        interface: String,
        orig_len: u32,
        wall: SystemTime,
    ) -> u64 {
        let d = crate::dissect::dissect(&data, link_type, None);
        let rec = PacketRecord {
            id: 0,
            at: Instant::now(),
            wall,
            interface,
            link_type,
            orig_len: if orig_len == 0 {
                data.len() as u32
            } else {
                orig_len
            },
            data,
            summary: d.summary,
            flags: d.flags,
            expert: d.expert,
            tree: Some(d.tree),
            decrypted: d.decrypted,
            fields: d.fields,
        };
        self.push(rec)
    }

    pub fn get(&self, index: usize) -> Option<&PacketRecord> {
        self.packets.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut PacketRecord> {
        self.packets.get_mut(index)
    }

    pub fn get_by_id(&self, id: u64) -> Option<&PacketRecord> {
        self.packets.iter().find(|p| p.id == id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PacketRecord> {
        self.packets.iter()
    }

    pub fn all(&self) -> Vec<&PacketRecord> {
        self.packets.iter().collect()
    }

    pub fn filtered<'a>(
        &'a self,
        pred: impl Fn(&PacketRecord) -> bool + 'a,
    ) -> impl Iterator<Item = (usize, &'a PacketRecord)> + 'a {
        self.packets
            .iter()
            .enumerate()
            .filter(move |(_, p)| pred(p))
    }
}

/// Intermediate result from L2/L3 walk.
#[derive(Debug, Clone)]
pub struct LayerResult<'a> {
    pub payload: &'a [u8],
    pub payload_offset: usize,
}
