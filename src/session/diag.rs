//! Diagnose session: DNS, TCP probe, TLS probe, ping, traceroute.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::net::TcpStream;

use crate::cli::DiagSpec;
use crate::frame::FrameBuffer;
use crate::inspect::InspectMode;
use crate::session::{ConnStatus, PaneFocus, SessionKind, SessionView};
use crate::transport::{CmdTx, IoEvent};

pub struct DiagSession {
    pub spec: DiagSpec,
    pub status: ConnStatus,
    pub frames: FrameBuffer,
    pub selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub inspect: InspectMode,
    pub lines: Vec<String>,
    pub status_msg: String,
    pub filter: String,
    pub running: bool,
    /// Set by app after open to trigger first run.
    pub needs_run: bool,
}

impl DiagSession {
    pub fn new(spec: DiagSpec) -> Self {
        Self {
            spec,
            status: ConnStatus::Idle,
            frames: FrameBuffer::new(100),
            selected: 0,
            follow: true,
            focus: PaneFocus::Log,
            inspect: InspectMode::Raw,
            lines: vec!["running diagnose…".into()],
            status_msg: "starting…".into(),
            filter: String::new(),
            running: false,
            needs_run: true,
        }
    }

    pub fn title_for(spec: &DiagSpec) -> String {
        match spec {
            DiagSpec::Dns { host } => format!("DNS {host}"),
            DiagSpec::Ping { host, port } => match port {
                Some(p) => format!("PING {host}:{p}"),
                None => format!("PING {host}"),
            },
            DiagSpec::Tcp { host, port } => format!("TCP {host}:{port}"),
            DiagSpec::Tls { host, port } => format!("TLS {host}:{port}"),
            DiagSpec::Trace { host, port } => match port {
                Some(p) => format!("TRACE {host}:{p}"),
                None => format!("TRACE {host}"),
            },
        }
    }

    pub async fn run_now(&mut self) {
        if self.running {
            return;
        }
        self.running = true;
        self.status = ConnStatus::Connecting;
        self.lines.clear();
        let result = match &self.spec {
            DiagSpec::Dns { host } => run_dns(host).await,
            DiagSpec::Ping { host, port } => run_ping(host, *port).await,
            DiagSpec::Tcp { host, port } => run_tcp_probe(host, *port).await,
            DiagSpec::Tls { host, port } => run_tls_probe(host, *port).await,
            DiagSpec::Trace { host, port } => run_traceroute(host, port.unwrap_or(80)).await,
        };
        match result {
            Ok(lines) => {
                self.lines = lines;
                self.status = ConnStatus::Connected;
                self.status_msg = "done".into();
            }
            Err(e) => {
                self.lines = vec![format!("error: {e:#}")];
                self.status = ConnStatus::Error;
                self.status_msg = "failed".into();
            }
        }
        self.running = false;
    }
}

async fn run_dns(host: &str) -> anyhow::Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut lines = vec![format!("DNS lookup: {host}")];
    match resolver.lookup_ip(host).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                lines.push(format!("  A/AAAA  {ip}"));
            }
        }
        Err(e) => lines.push(format!("  lookup_ip error: {e}")),
    }
    if let Ok(mx) = resolver.mx_lookup(host).await {
        for r in mx.iter() {
            lines.push(format!("  MX  {} {}", r.preference(), r.exchange()));
        }
    }
    Ok(lines)
}

async fn run_tcp_probe(host: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let addr = crate::cli::join_host_port(host, port);
    let start = Instant::now();
    match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let ms = start.elapsed().as_millis();
            let peer = stream.peer_addr().ok();
            Ok(vec![
                format!("TCP connect {addr}"),
                "  result: OK".to_string(),
                format!("  handshake: {ms} ms"),
                format!("  peer: {peer:?}"),
            ])
        }
        Ok(Err(e)) => Ok(vec![
            format!("TCP connect {addr}"),
            format!("  result: FAIL ({e})"),
            format!("  after: {} ms", start.elapsed().as_millis()),
        ]),
        Err(_) => Ok(vec![
            format!("TCP connect {addr}"),
            "  result: TIMEOUT (5s)".into(),
        ]),
    }
}

async fn run_tls_probe(host: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let info = crate::tlsinfo::probe_tls(host, port).await?;
    let mut lines = vec![format!("TLS probe {host}:{port}")];
    lines.extend(crate::tlsinfo::format_tls_info(&info));
    Ok(lines)
}

async fn run_ping(host: &str, port: Option<u16>) -> anyhow::Result<Vec<String>> {
    // Try ICMP via surge-ping; fall back to TCP ping.
    let mut lines = vec![format!("ping {host}")];
    match try_icmp_ping(host).await {
        Ok(ms_list) => {
            lines.push("  method: ICMP".into());
            for (i, ms) in ms_list.iter().enumerate() {
                lines.push(format!("  seq={} time={} ms", i + 1, ms));
            }
        }
        Err(e) => {
            lines.push(format!("  ICMP unavailable ({e}); falling back to TCP"));
            let p = port.unwrap_or(80);
            let tcp_lines = run_tcp_probe(host, p).await?;
            lines.extend(tcp_lines);
        }
    }
    Ok(lines)
}

async fn try_icmp_ping(host: &str) -> anyhow::Result<Vec<u64>> {
    use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
    let ip = tokio::net::lookup_host((host, 0u16))
        .await?
        .next()
        .map(|s: SocketAddr| s.ip())
        .ok_or_else(|| anyhow::anyhow!("no addresses"))?;
    let config = match ip {
        std::net::IpAddr::V4(_) => Config::builder().kind(ICMP::V4).build(),
        std::net::IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
    };
    let client = Client::new(&config)?;
    let mut pinger = client.pinger(ip, PingIdentifier(0x4242)).await;
    let mut times = Vec::new();
    for i in 0..4u16 {
        let payload = [0u8; 56];
        match pinger.ping(PingSequence(i), &payload).await {
            Ok((_, dur)) => times.push(dur.as_millis() as u64),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(times)
}

async fn run_traceroute(host: &str, port: u16) -> anyhow::Result<Vec<String>> {
    let dest = resolve_one(host).await?;
    let mut lines = vec![format!(
        "traceroute to {host} ({dest}), 30 hops max, port {port}"
    )];
    match traceroute_hops(dest, port, 30).await {
        Ok(hops) => {
            for hop in hops {
                lines.push(format_hop(&hop));
            }
        }
        Err(e) => {
            lines.push(format!(
                "  icmp/UDP traceroute unavailable ({e})"
            ));
            lines.push(
                "  hint: need CAP_NET_RAW/root for ICMP TTL probes; falling back to TCP TTL"
                    .into(),
            );
            match tcp_ttl_traceroute(dest, port, 30).await {
                Ok(hops) => {
                    let all_star = hops.iter().all(|h| h.addr.is_none());
                    for hop in hops {
                        lines.push(format_hop(&hop));
                    }
                    if all_star {
                        lines.push(
                            "  note: all hops timed out — check firewall or try `tcp://host:port`"
                                .into(),
                        );
                    }
                }
                Err(e2) => {
                    lines.push(format!("  TCP TTL probes failed: {e2}"));
                    lines.push(
                        "  falling back to DNS + TCP connect probe (no hop table without raw sockets)"
                            .into(),
                    );
                    lines.extend(run_dns(host).await?);
                    lines.extend(run_tcp_probe(host, port).await?);
                }
            }
        }
    }
    Ok(lines)
}

#[derive(Debug, Clone)]
struct TraceHop {
    ttl: u8,
    addr: Option<std::net::IpAddr>,
    rtt_ms: Option<u64>,
    note: String,
}

fn format_hop(hop: &TraceHop) -> String {
    let addr = hop
        .addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "*".into());
    match hop.rtt_ms {
        Some(ms) => format!("  {:>2}  {addr}  {ms} ms{}", hop.ttl, hop.note),
        None => format!("  {:>2}  {addr}  *{}", hop.ttl, hop.note),
    }
}

async fn resolve_one(host: &str) -> anyhow::Result<std::net::IpAddr> {
    tokio::net::lookup_host((host, 0u16))
        .await?
        .next()
        .map(|s| s.ip())
        .ok_or_else(|| anyhow::anyhow!("no addresses for {host}"))
}

async fn traceroute_hops(
    dest: std::net::IpAddr,
    port: u16,
    max_hops: u8,
) -> anyhow::Result<Vec<TraceHop>> {
    tokio::task::spawn_blocking(move || traceroute_icmp_udp(dest, port, max_hops))
        .await
        .map_err(|e| anyhow::anyhow!("traceroute join: {e}"))?
}

fn traceroute_icmp_udp(
    dest: std::net::IpAddr,
    port: u16,
    max_hops: u8,
) -> anyhow::Result<Vec<TraceHop>> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    let domain = match dest {
        std::net::IpAddr::V4(_) => Domain::IPV4,
        std::net::IpAddr::V6(_) => Domain::IPV6,
    };
    let icmp_proto = match dest {
        std::net::IpAddr::V4(_) => Protocol::ICMPV4,
        std::net::IpAddr::V6(_) => Protocol::ICMPV6,
    };
    let icmp = Socket::new(domain, Type::RAW, Some(icmp_proto))
        .map_err(|e| anyhow::anyhow!("raw ICMP socket: {e}"))?;
    icmp.set_read_timeout(Some(Duration::from_millis(800)))?;

    let mut hops = Vec::new();
    for ttl in 1..=max_hops {
        let udp = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        match dest {
            std::net::IpAddr::V4(_) => udp.set_ttl_v4(ttl as u32)?,
            std::net::IpAddr::V6(_) => udp.set_unicast_hops_v6(ttl as u32)?,
        }
        let bind_addr = match dest {
            std::net::IpAddr::V4(_) => SockAddr::from(SocketAddr::from(([0, 0, 0, 0], 0))),
            std::net::IpAddr::V6(_) => SockAddr::from(SocketAddr::from(([0u8; 16], 0))),
        };
        udp.bind(&bind_addr)?;
        let probe_port = if port == 0 { 33434 + ttl as u16 } else { port };
        let start = Instant::now();
        let dest_addr = SockAddr::from(SocketAddr::new(dest, probe_port));
        let _ = udp.send_to(b"bitbeak-trace", &dest_addr);
        let mut buf: [MaybeUninit<u8>; 1500] = unsafe { MaybeUninit::uninit().assume_init() };
        match icmp.recv_from(&mut buf) {
            Ok((n, from)) => {
                let rtt = start.elapsed().as_millis() as u64;
                let from_ip = from.as_socket().map(|s| s.ip()).unwrap_or(dest);
                let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                let reached = from_ip == dest || icmp_is_dest_unreachable(slice, dest);
                hops.push(TraceHop {
                    ttl,
                    addr: Some(from_ip),
                    rtt_ms: Some(rtt),
                    note: if reached {
                        "  (destination)".into()
                    } else {
                        String::new()
                    },
                });
                if reached {
                    break;
                }
            }
            Err(_) => {
                hops.push(TraceHop {
                    ttl,
                    addr: None,
                    rtt_ms: None,
                    note: String::new(),
                });
            }
        }
    }
    Ok(hops)
}

fn icmp_is_dest_unreachable(packet: &[u8], _dest: std::net::IpAddr) -> bool {
    // IPv4: IP header + ICMP type 3 (dest unreachable) or type 11 (time exceeded).
    // Prefer detecting type 3 as "reached" when UDP port is closed.
    if packet.len() < 20 {
        return false;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl + 1 {
        // Maybe bare ICMP
        return matches!(packet.first().copied(), Some(3));
    }
    let icmp_type = packet[ihl];
    icmp_type == 3
}

async fn tcp_ttl_traceroute(
    dest: std::net::IpAddr,
    port: u16,
    max_hops: u8,
) -> anyhow::Result<Vec<TraceHop>> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    let mut hops = Vec::new();
    let target = SocketAddr::new(dest, if port == 0 { 80 } else { port });
    for ttl in 1..=max_hops {
        let domain = match dest {
            std::net::IpAddr::V4(_) => Domain::IPV4,
            std::net::IpAddr::V6(_) => Domain::IPV6,
        };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        match dest {
            std::net::IpAddr::V4(_) => sock.set_ttl_v4(ttl as u32)?,
            std::net::IpAddr::V6(_) => sock.set_unicast_hops_v6(ttl as u32)?,
        }
        sock.set_nonblocking(true)?;
        let start = Instant::now();
        let addr = SockAddr::from(target);
        let connect_res = sock.connect(&addr);
        let timed_out = match connect_res {
            Ok(()) => false,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                sock.set_write_timeout(Some(Duration::from_millis(600)))?;
                // Wait briefly for connect completion.
                tokio::time::sleep(Duration::from_millis(600)).await;
                match sock.take_error()? {
                    Some(_) => true,
                    None => {
                        // Check if connected by trying peer_addr via into_tcp.
                        false
                    }
                }
            }
            Err(_) => true,
        };
        let rtt = start.elapsed().as_millis() as u64;
        if timed_out && rtt >= 500 {
            hops.push(TraceHop {
                ttl,
                addr: None,
                rtt_ms: None,
                note: "  (ttl expired / no reply)".into(),
            });
        } else {
            hops.push(TraceHop {
                ttl,
                addr: Some(dest),
                rtt_ms: Some(rtt.min(600)),
                note: "  (destination or RST)".into(),
            });
            break;
        }
    }
    Ok(hops)
}

impl SessionView for DiagSession {
    fn kind(&self) -> SessionKind {
        SessionKind::Diag
    }

    fn title(&self) -> String {
        Self::title_for(&self.spec)
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn target_display(&self) -> String {
        Self::title_for(&self.spec)
    }

    fn frames(&self) -> &FrameBuffer {
        &self.frames
    }

    fn frames_mut(&mut self) -> &mut FrameBuffer {
        &mut self.frames
    }

    fn inspect_mode(&self) -> InspectMode {
        self.inspect
    }

    fn set_inspect_mode(&mut self, mode: InspectMode) {
        self.inspect = mode;
    }

    fn selected_index(&self) -> usize {
        self.selected
    }

    fn set_selected_index(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn follow(&self) -> bool {
        self.follow
    }

    fn set_follow(&mut self, follow: bool) {
        self.follow = follow;
    }

    fn focus(&self) -> PaneFocus {
        self.focus
    }

    fn set_focus(&mut self, focus: PaneFocus) {
        self.focus = focus;
    }

    fn on_io(&mut self, _event: IoEvent) {}

    fn cmd_tx(&self) -> Option<&CmdTx> {
        None
    }

    fn status_message(&self) -> &str {
        &self.status_msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_hop_star_and_addr() {
        let star = TraceHop {
            ttl: 1,
            addr: None,
            rtt_ms: None,
            note: String::new(),
        };
        assert!(format_hop(&star).contains('*'));
        let hop = TraceHop {
            ttl: 2,
            addr: Some("1.2.3.4".parse().unwrap()),
            rtt_ms: Some(12),
            note: String::new(),
        };
        let s = format_hop(&hop);
        assert!(s.contains("1.2.3.4"));
        assert!(s.contains("12 ms"));
    }
}
