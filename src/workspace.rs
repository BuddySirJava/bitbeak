//! Workspace: concurrent typed sessions as tabs.

use std::time::{Duration, Instant};

use tui_textarea::TextArea;

use crate::bench::BenchResult;
use crate::cli::{Args, DiagSpec, Target};
use crate::collections::Collection;
use crate::framing::FramingConfig;
use crate::session::{
    default_routes, load_routes, CaptureSession, ConnStatus, DiagSession, HttpSession,
    ListenSession, MockSession, ProxySession, SessionKind, SessionView, StreamSession,
};
use crate::transport::IoRx;
use crate::ui::hitmap::HitMap;
use crate::ui::textarea_util;

#[allow(clippy::large_enum_variant)]
pub enum SessionSlot {
    Stream(StreamSession),
    Http(HttpSession),
    Listen(ListenSession),
    Proxy(ProxySession),
    Diag(DiagSession),
    Capture(CaptureSession),
    Mock(MockSession),
}

impl SessionSlot {
    pub fn kind(&self) -> SessionKind {
        match self {
            Self::Stream(_) => SessionKind::Stream,
            Self::Http(_) => SessionKind::Http,
            Self::Listen(_) => SessionKind::Listen,
            Self::Proxy(_) => SessionKind::Proxy,
            Self::Diag(_) => SessionKind::Diag,
            Self::Capture(s) => s.kind(),
            Self::Mock(s) => s.kind(),
        }
    }

    pub fn title(&self) -> String {
        match self {
            Self::Stream(s) => s.title(),
            Self::Http(s) => s.title(),
            Self::Listen(s) => s.title(),
            Self::Proxy(s) => s.title(),
            Self::Diag(s) => s.title(),
            Self::Capture(s) => s.title(),
            Self::Mock(s) => s.title(),
        }
    }

    pub fn conn_status(&self) -> ConnStatus {
        match self {
            Self::Stream(s) => s.status,
            Self::Http(s) => s.status,
            Self::Listen(s) => s.status,
            Self::Proxy(s) => s.status,
            Self::Diag(s) => s.status,
            Self::Capture(s) => s.status,
            Self::Mock(s) => s.status,
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self.conn_status(),
            ConnStatus::Connected | ConnStatus::Listening | ConnStatus::Connecting
        )
    }

    /// Middle-ellipsis truncation for tab titles.
    pub fn short_tab(&self, idx: usize) -> String {
        let label = self.kind().label();
        let target = match self {
            Self::Stream(s) => s.target.display(),
            Self::Http(s) => textarea_util::text_of(&s.url),
            Self::Listen(s) => s.target.display(),
            Self::Proxy(s) => s.bind.display(),
            Self::Diag(s) => DiagSession::title_for(&s.spec),
            Self::Capture(s) => s.title_iface.clone(),
            Self::Mock(s) => s.bind.clone(),
        };
        let short = middle_truncate(&target, 18);
        let dot = if self.is_live() { "●" } else { "○" };
        format!("{idx_1} {dot} {label} {short}", idx_1 = idx + 1)
    }

    pub fn take_io_rx(&mut self) -> Option<IoRx> {
        match self {
            Self::Stream(s) => s.take_io_rx(),
            Self::Listen(s) => s.take_io_rx(),
            Self::Proxy(s) => s.take_io_rx(),
            Self::Mock(s) => s.take_io_rx(),
            _ => None,
        }
    }

    pub fn on_io(&mut self, event: crate::transport::IoEvent) {
        match self {
            Self::Stream(s) => s.on_io(event),
            Self::Listen(s) => s.on_io(event),
            Self::Proxy(s) => s.on_io(event),
            Self::Http(s) => s.on_io(event),
            Self::Diag(s) => s.on_io(event),
            Self::Capture(_) => {}
            Self::Mock(s) => s.on_io(event),
        }
    }

    pub fn status_label(&self) -> &'static str {
        self.conn_status().label()
    }

    pub fn status_message(&self) -> &str {
        match self {
            Self::Stream(s) => s.status_message(),
            Self::Http(s) => s.status_message(),
            Self::Listen(s) => s.status_message(),
            Self::Proxy(s) => s.status_message(),
            Self::Diag(s) => s.status_message(),
            Self::Capture(s) => &s.status_msg,
            Self::Mock(s) => &s.status_msg,
        }
    }

    pub fn frame_count(&self) -> usize {
        match self {
            Self::Stream(s) => s.frames.len(),
            Self::Http(s) => s.frames.len(),
            Self::Listen(s) => s.frames.len(),
            Self::Proxy(s) => s.frames.len(),
            Self::Diag(s) => s.lines.len(),
            Self::Capture(s) => s.store.len(),
            Self::Mock(s) => s.frames.len(),
        }
    }

    pub fn target_display(&self) -> String {
        match self {
            Self::Stream(s) => s.target_display(),
            Self::Http(s) => s.target_display(),
            Self::Listen(s) => s.target_display(),
            Self::Proxy(s) => s.target_display(),
            Self::Diag(s) => s.target_display(),
            Self::Capture(s) => s.title_iface.clone(),
            Self::Mock(s) => s.bind.clone(),
        }
    }

    pub fn filter(&self) -> &str {
        match self {
            Self::Stream(s) => &s.filter,
            Self::Http(s) => &s.filter,
            Self::Listen(s) => &s.filter,
            Self::Proxy(s) => &s.filter,
            Self::Diag(s) => &s.filter,
            Self::Capture(s) => &s.display_filter_str,
            Self::Mock(_) => "",
        }
    }

    pub fn set_filter(&mut self, q: String) {
        match self {
            Self::Stream(s) => s.filter = q,
            Self::Http(s) => s.filter = q,
            Self::Listen(s) => s.filter = q,
            Self::Proxy(s) => s.filter = q,
            Self::Diag(s) => s.filter = q,
            Self::Capture(s) => {
                let _ = s.set_display_filter(&q);
            }
            Self::Mock(_) => {}
        }
    }
}

fn middle_truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    if max < 4 {
        return s.chars().take(max).collect();
    }
    let keep = max - 1;
    let head = keep / 2;
    let tail = keep - head;
    format!("{}…{}", &s[..head], &s[s.len() - tail..])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Overlay {
    #[default]
    None,
    Help,
    NewSession,
    /// Kind index into NEW_KINDS; URI entry form.
    NewSessionUri {
        kind: usize,
    },
    Quit,
    Filter,
    Collections,
    Bench,
    Fuzz,
    CommandPalette,
    /// Confirm closing a live tab.
    CloseConfirm,
    FollowStream,
    Conversations,
    Endpoints,
    Hierarchy,
    Expert,
    Keylog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashKind {
    Info,
    Ok,
    Err,
}

pub struct Workspace {
    pub sessions: Vec<SessionSlot>,
    pub active: usize,
    pub overlay: Overlay,
    pub quit_yes: bool,
    pub close_yes: bool,
    pub filter_input: TextArea<'static>,
    pub new_session_cursor: usize,
    pub palette_input: TextArea<'static>,
    /// URI field for NewSessionUri (and bind for proxy).
    pub uri_input: TextArea<'static>,
    /// Upstream field for proxy kind.
    pub uri_input2: TextArea<'static>,
    /// 0 = primary URI, 1 = upstream (proxy only).
    pub uri_field: usize,
    pub collection: Option<Collection>,
    pub collection_names: Vec<String>,
    pub collection_cursor: usize,
    /// When true, Collections overlay lists requests in the loaded collection.
    pub collection_show_requests: bool,
    pub request_cursor: usize,
    pub bench_result: Option<BenchResult>,
    pub fuzz_seed: u64,
    pub status_flash: String,
    pub flash_kind: FlashKind,
    pub flash_at: Option<Instant>,
    pub max_frames: usize,
    pub framing: FramingConfig,
    pub pcap_path: Option<std::path::PathBuf>,
    pub hitmap: HitMap,
    pub tick: u64,
}

impl Workspace {
    pub const FLASH_SECS: u64 = 4;

    pub fn new(args: &Args) -> anyhow::Result<Self> {
        let framing = FramingConfig::from_args(args.framing, args.prefix_size, args.prefix_endian);
        let mut ws = Self {
            sessions: Vec::new(),
            active: 0,
            overlay: Overlay::None,
            quit_yes: true,
            close_yes: true,
            filter_input: textarea_util::single_line(""),
            new_session_cursor: 0,
            palette_input: textarea_util::single_line(""),
            uri_input: textarea_util::single_line(""),
            uri_input2: textarea_util::single_line(""),
            uri_field: 0,
            collection: None,
            collection_names: crate::collections::list_collections().unwrap_or_default(),
            collection_cursor: 0,
            collection_show_requests: false,
            request_cursor: 0,
            bench_result: None,
            fuzz_seed: 1,
            status_flash: String::new(),
            flash_kind: FlashKind::Info,
            flash_at: None,
            max_frames: args.max_frames,
            framing: framing.clone(),
            pcap_path: args.pcap.clone(),
            hitmap: HitMap::default(),
            tick: 0,
        };

        if let Some(name) = &args.collection {
            match crate::collections::load_collection(name) {
                Ok(c) => {
                    ws.flash_ok(format!("loaded collection {}", c.name));
                    ws.collection = Some(c);
                }
                Err(e) => ws.flash_err(format!("collection: {e:#}")),
            }
        }

        if let Some(iface) = &args.capture {
            let mut cap = CaptureSession::new_live(iface, args.max_frames);
            if let Some(cf) = &args.capture_filter {
                let _ = cap.set_capture_filter(cf);
            }
            if args.ring_size > 0 {
                let dir = dirs::cache_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("bitbeak")
                    .join("ring");
                let _ = cap.enable_ring(dir, args.ring_size, args.ring_files);
            }
            if let Some(kl) = &args.keylog {
                let _ = cap.load_keylog(kl);
            }
            ws.sessions.push(SessionSlot::Capture(cap));
        } else if let Some(path) = &args.open {
            match CaptureSession::open_file(path, args.max_frames) {
                Ok(mut cap) => {
                    if let Some(kl) = &args.keylog {
                        let _ = cap.load_keylog(kl);
                    }
                    ws.sessions.push(SessionSlot::Capture(cap));
                }
                Err(e) => ws.flash_err(format!("open: {e:#}")),
            }
        } else if let Some(diag) = &args.diag {
            let spec: DiagSpec = diag.parse()?;
            ws.sessions.push(SessionSlot::Diag(DiagSession::new(spec)));
        } else if let (Some(proxy), Some(upstream)) = (&args.proxy, &args.upstream) {
            let bind: Target = proxy.parse()?;
            let up: Target = upstream.parse()?;
            ws.sessions.push(SessionSlot::Proxy(ProxySession::start(
                bind,
                up,
                args.max_frames,
                args.tls_intercept,
            )));
        } else if let Some(target_str) = &args.target {
            let target: Target = target_str.parse()?;
            if args.listen {
                ws.sessions.push(SessionSlot::Listen(ListenSession::start(
                    target,
                    framing.clone(),
                    args.max_frames,
                )));
            } else if target.is_http() {
                ws.sessions
                    .push(SessionSlot::Http(HttpSession::new(target, args.max_frames)));
            } else {
                ws.sessions.push(SessionSlot::Stream(StreamSession::start(
                    target,
                    framing.clone(),
                    args.max_frames,
                )));
            }
        }

        Ok(ws)
    }

    pub fn flash(&mut self, msg: impl Into<String>, kind: FlashKind) {
        self.status_flash = msg.into();
        self.flash_kind = kind;
        self.flash_at = Some(Instant::now());
    }

    pub fn flash_ok(&mut self, msg: impl Into<String>) {
        self.flash(msg, FlashKind::Ok);
    }

    pub fn flash_err(&mut self, msg: impl Into<String>) {
        self.flash(msg, FlashKind::Err);
    }

    pub fn flash_info(&mut self, msg: impl Into<String>) {
        self.flash(msg, FlashKind::Info);
    }

    pub fn tick_flash(&mut self) {
        if let Some(at) = self.flash_at {
            if at.elapsed() >= Duration::from_secs(Self::FLASH_SECS) {
                self.status_flash.clear();
                self.flash_at = None;
            }
        }
    }

    pub fn active_session(&self) -> Option<&SessionSlot> {
        self.sessions.get(self.active)
    }

    pub fn active_session_mut(&mut self) -> Option<&mut SessionSlot> {
        self.sessions.get_mut(self.active)
    }

    pub fn next_tab(&mut self) {
        if !self.sessions.is_empty() {
            self.active = (self.active + 1) % self.sessions.len();
        }
    }

    pub fn prev_tab(&mut self) {
        if !self.sessions.is_empty() {
            self.active = if self.active == 0 {
                self.sessions.len() - 1
            } else {
                self.active - 1
            };
        }
    }

    pub fn close_active(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        if let SessionSlot::Capture(s) = &mut self.sessions[self.active] {
            s.stop_capture();
        }
        self.sessions.remove(self.active);
        if self.active >= self.sessions.len() && !self.sessions.is_empty() {
            self.active = self.sessions.len() - 1;
        }
        if self.sessions.is_empty() {
            self.active = 0;
        }
        self.overlay = Overlay::None;
    }

    pub fn request_close_active(&mut self) {
        let needs_confirm = self.active_session().map(|s| s.is_live()).unwrap_or(false);
        if needs_confirm {
            self.close_yes = true;
            self.overlay = Overlay::CloseConfirm;
        } else {
            self.close_active();
        }
    }

    pub fn open_stream(&mut self, target: Target) {
        self.sessions.push(SessionSlot::Stream(StreamSession::start(
            target,
            self.framing.clone(),
            self.max_frames,
        )));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn open_http(&mut self, target: Target) {
        self.sessions
            .push(SessionSlot::Http(HttpSession::new(target, self.max_frames)));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn open_listen(&mut self, target: Target) {
        self.sessions.push(SessionSlot::Listen(ListenSession::start(
            target,
            self.framing.clone(),
            self.max_frames,
        )));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn open_diag(&mut self, spec: DiagSpec) {
        self.sessions
            .push(SessionSlot::Diag(DiagSession::new(spec)));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn open_proxy(&mut self, bind: Target, upstream: Target) {
        self.sessions.push(SessionSlot::Proxy(ProxySession::start(
            bind,
            upstream,
            self.max_frames,
            false,
        )));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn open_capture(&mut self, iface: &str) {
        self.sessions
            .push(SessionSlot::Capture(CaptureSession::new_live(
                iface,
                self.max_frames,
            )));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn open_capture_file(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        let cap = CaptureSession::open_file(path, self.max_frames)?;
        self.sessions.push(SessionSlot::Capture(cap));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
        Ok(())
    }

    pub fn open_mock(&mut self, bind: Target) {
        let bind_key = match &bind {
            Target::Tcp { host, port } => format!("{host}:{port}"),
            _ => "127.0.0.1:18080".into(),
        };
        let routes = load_routes(&bind_key).unwrap_or_else(default_routes);
        self.sessions.push(SessionSlot::Mock(MockSession::start(
            bind,
            self.max_frames,
            routes,
        )));
        self.active = self.sessions.len() - 1;
        self.overlay = Overlay::None;
    }

    pub fn begin_uri_entry(&mut self, kind: usize) {
        self.uri_input = textarea_util::single_line("");
        self.uri_input2 = textarea_util::single_line("");
        self.uri_field = 0;
        textarea_util::style_focused(&mut self.uri_input);
        self.overlay = Overlay::NewSessionUri { kind };
    }

    pub fn uri_hint(kind: usize) -> &'static str {
        match kind {
            0 => "e.g. tcp://127.0.0.1:9090  unix:///tmp/app.sock  ws://host/path  tls://host:443",
            1 => "e.g. https://api.example.com/v1/health",
            2 => "e.g. tcp://0.0.0.0:9090  unix:///tmp/debug.sock",
            3 => "bind URI (Tab for upstream)  e.g. tcp://127.0.0.1:8080",
            4 => "e.g. dns://example.com  ping://8.8.8.8  tcp://host:443  tls://host:443",
            5 => "e.g. eth0  en0  any  (live capture on interface)",
            6 => "e.g. /path/to/capture.pcap  or  capture.pcapng",
            7 => "e.g. tcp://127.0.0.1:18080  (mock HTTP server bind)",
            _ => "",
        }
    }

    pub const NEW_KINDS: [&'static str; 8] = [
        "Stream (tcp/udp/unix/ws/tls URI)",
        "HTTP / HTTPS",
        "Listen (multi-client)",
        "Proxy / tap",
        "Diagnose (dns/ping/tcp/tls)",
        "Capture (live iface)",
        "Open capture file",
        "Mock HTTP server",
    ];
}
