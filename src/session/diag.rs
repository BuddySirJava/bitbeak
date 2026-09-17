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
    let addr = format!("{host}:{port}");
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
    let ip = tokio::net::lookup_host(format!("{host}:0"))
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
    // Best-effort TTL probe using TCP connect with increasing TTL via socket2 isn't trivial
    // without extra crates; approximate with sequential connect notes.
    let mut lines = vec![
        format!("traceroute (TCP-ish) to {host}:{port}"),
        "  note: full TTL traceroute needs raw sockets; showing path via DNS + TCP probe".into(),
    ];
    lines.extend(run_dns(host).await?);
    lines.extend(run_tcp_probe(host, port).await?);
    Ok(lines)
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
