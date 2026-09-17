//! Cross-platform live capture trait and dispatch.

use std::time::SystemTime;

use anyhow::Result;
use bytes::Bytes;

use crate::capture::cap_filter::CaptureFilter;
use crate::dissect::packet::LinkType;

#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name: String,
    pub description: String,
    pub is_up: bool,
    pub mac: Option<[u8; 6]>,
}

#[derive(Debug, Clone)]
pub struct CapturePacket {
    pub data: Bytes,
    pub link_type: LinkType,
    pub interface: String,
    pub orig_len: u32,
    pub wall: SystemTime,
}

pub trait LiveCapture: Send {
    fn next_packet(&mut self) -> Result<Option<CapturePacket>>;
    fn inject(&mut self, _frame: &[u8]) -> Result<()> {
        anyhow::bail!("packet inject not supported on this backend");
    }
    fn interface(&self) -> &str;
    fn link_type(&self) -> LinkType;
}

pub struct CaptureHandle {
    inner: Box<dyn LiveCapture>,
}

impl CaptureHandle {
    pub fn next_packet(&mut self) -> Result<Option<CapturePacket>> {
        self.inner.next_packet()
    }
    pub fn inject(&mut self, frame: &[u8]) -> Result<()> {
        self.inner.inject(frame)
    }
    pub fn interface(&self) -> &str {
        self.inner.interface()
    }
    pub fn link_type(&self) -> LinkType {
        self.inner.link_type()
    }
}

pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    #[cfg(target_os = "linux")]
    {
        crate::capture::linux::list_interfaces()
    }
    #[cfg(target_os = "macos")]
    {
        crate::capture::macos::list_interfaces()
    }
    #[cfg(windows)]
    {
        crate::capture::windows::list_interfaces()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Ok(Vec::new())
    }
}

pub fn open_live(name: &str, snaplen: i32, promiscuous: bool) -> Result<CaptureHandle> {
    open_live_filtered(name, snaplen, promiscuous, None)
}

pub fn open_live_filtered(
    name: &str,
    snaplen: i32,
    promiscuous: bool,
    filter: Option<&CaptureFilter>,
) -> Result<CaptureHandle> {
    if let Some(rpcap) = parse_rpcap_target(name) {
        let c = crate::capture::rpcap::RpcapCapture::open(&rpcap.host, rpcap.port, &rpcap.iface)?;
        return Ok(CaptureHandle { inner: Box::new(c) });
    }
    #[cfg(target_os = "linux")]
    {
        let c = crate::capture::linux::LinuxCapture::open_with_filter(
            name,
            snaplen,
            promiscuous,
            filter,
        )?;
        Ok(CaptureHandle { inner: Box::new(c) })
    }
    #[cfg(target_os = "macos")]
    {
        let mut c = crate::capture::macos::MacCapture::open(name, snaplen, promiscuous)?;
        if let Some(f) = filter {
            c.set_filter(f)?;
        }
        Ok(CaptureHandle { inner: Box::new(c) })
    }
    #[cfg(windows)]
    {
        let filter_str = filter.and_then(capture_filter_to_pcap);
        let c = crate::capture::windows::WinCapture::open(
            name,
            snaplen,
            promiscuous,
            filter_str.as_deref(),
        )?;
        Ok(CaptureHandle { inner: Box::new(c) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (name, snaplen, promiscuous, filter);
        anyhow::bail!("live capture is not supported on this platform");
    }
}

struct RpcapTarget {
    host: String,
    port: u16,
    iface: String,
}

/// Parse `rpcap://host:port/iface` or `rpcap://host/iface` (port 2002).
fn parse_rpcap_target(name: &str) -> Option<RpcapTarget> {
    let rest = name.strip_prefix("rpcap://")?;
    let (hostport, iface) = rest.split_once('/')?;
    if iface.is_empty() {
        return None;
    }
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        // IPv6 not supported in this shorthand
        (h.to_string(), p.parse().unwrap_or(2002))
    } else {
        (hostport.to_string(), 2002)
    };
    Some(RpcapTarget {
        host,
        port,
        iface: iface.to_string(),
    })
}

#[cfg(windows)]
fn capture_filter_to_pcap(filter: &CaptureFilter) -> Option<String> {
    match filter {
        CaptureFilter::True => None,
        CaptureFilter::Proto(p) => Some((*p).to_string()),
        CaptureFilter::Port(p) => Some(format!("port {p}")),
        CaptureFilter::SrcPort(p) => Some(format!("src port {p}")),
        CaptureFilter::DstPort(p) => Some(format!("dst port {p}")),
        CaptureFilter::Host(ip) => Some(format!("host {ip}")),
        CaptureFilter::SrcHost(ip) => Some(format!("src host {ip}")),
        CaptureFilter::DstHost(ip) => Some(format!("dst host {ip}")),
        CaptureFilter::And(a, b) => {
            let l = capture_filter_to_pcap(a)?;
            let r = capture_filter_to_pcap(b)?;
            Some(format!("({l}) and ({r})"))
        }
        CaptureFilter::Or(a, b) => {
            let l = capture_filter_to_pcap(a)?;
            let r = capture_filter_to_pcap(b)?;
            Some(format!("({l}) or ({r})"))
        }
        CaptureFilter::Not(f) => capture_filter_to_pcap(f).map(|s| format!("not ({s})")),
        CaptureFilter::Net { .. } => None,
    }
}

/// Permission / setup hint for the current OS.
pub fn capture_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "need CAP_NET_RAW (sudo or setcap cap_net_raw,cap_net_admin=eip)"
    }
    #[cfg(target_os = "macos")]
    {
        "need root or BPF group access to /dev/bpf*"
    }
    #[cfg(windows)]
    {
        "Npcap required — BitBeak can download the official installer"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        "live capture unsupported"
    }
}
