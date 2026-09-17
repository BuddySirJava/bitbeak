//! Local proxy / tap session (TCP splice).

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::cli::Target;
use crate::frame::{Direction, FrameBuffer};
use crate::inspect::InspectMode;
use crate::session::{ConnStatus, PaneFocus, SessionKind, SessionView};
use crate::transport::{CmdTx, IoEvent, IoRx};

pub struct ProxySession {
    pub bind: Target,
    pub upstream: Target,
    pub status: ConnStatus,
    pub frames: FrameBuffer,
    pub selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub inspect: InspectMode,
    pub filter: String,
    pub status_msg: String,
    pub tls_intercept: bool,
    pub io_rx: Option<IoRx>,
    cmd_tx: Option<CmdTx>,
    _handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProxySession {
    pub fn start(bind: Target, upstream: Target, max_frames: usize, tls_intercept: bool) -> Self {
        let (io_tx, io_rx) = mpsc::unbounded_channel();
        let bind_c = bind.clone();
        let upstream_c = upstream.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_tcp_proxy(bind_c, upstream_c, io_tx).await {
                let _ = e;
            }
        });
        Self {
            bind,
            upstream,
            status: ConnStatus::Listening,
            frames: FrameBuffer::new(max_frames),
            selected: 0,
            follow: true,
            focus: PaneFocus::Log,
            inspect: InspectMode::Hex,
            filter: String::new(),
            status_msg: if tls_intercept {
                "proxy up (tls intercept requested — plain splice in v0.1 core)".into()
            } else {
                "proxy listening…".into()
            },
            tls_intercept,
            io_rx: Some(io_rx),
            cmd_tx: None,
            _handle: Some(handle),
        }
    }

    pub fn take_io_rx(&mut self) -> Option<IoRx> {
        self.io_rx.take()
    }
}

async fn run_tcp_proxy(
    bind: Target,
    upstream: Target,
    io_tx: crate::transport::IoTx,
) -> Result<()> {
    let (host, port) = match &bind {
        Target::Tcp { host, port } => (host.clone(), *port),
        _ => anyhow::bail!("proxy bind must be tcp://"),
    };
    let (up_host, up_port) = match &upstream {
        Target::Tcp { host, port } => (host.clone(), *port),
        _ => anyhow::bail!("proxy upstream must be tcp://"),
    };

    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let _ = io_tx.send(IoEvent::Status {
        message: format!("proxy {addr} → {up_host}:{up_port}"),
    });
    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("listen:{addr}"),
    });

    loop {
        let (client, peer) = listener.accept().await?;
        let io_tx2 = io_tx.clone();
        let up_host = up_host.clone();
        tokio::spawn(async move {
            let _ = io_tx2.send(IoEvent::ClientJoined {
                id: 1,
                peer: peer.to_string(),
            });
            match TcpStream::connect((up_host.as_str(), up_port)).await {
                Ok(server) => {
                    if let Err(e) = splice(client, server, io_tx2.clone()).await {
                        let _ = io_tx2.send(IoEvent::Error {
                            message: e.to_string(),
                        });
                    }
                }
                Err(e) => {
                    let _ = io_tx2.send(IoEvent::Error {
                        message: format!("upstream connect: {e}"),
                    });
                }
            }
            let _ = io_tx2.send(IoEvent::ClientLeft { id: 1 });
        });
    }
}

async fn splice(client: TcpStream, server: TcpStream, io_tx: crate::transport::IoTx) -> Result<()> {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let active = Arc::new(Mutex::new(true));

    let io1 = io_tx.clone();
    let a1 = active.clone();
    let c2s = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        while *a1.lock().await {
            match cr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    let _ = io1.send(IoEvent::Frame {
                        direction: Direction::Out,
                        payload: payload.clone(),
                        peer: Some("C→S".into()),
                    });
                    if sw.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        *a1.lock().await = false;
    });

    let io2 = io_tx;
    let a2 = active;
    let s2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        while *a2.lock().await {
            match sr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    let _ = io2.send(IoEvent::Frame {
                        direction: Direction::In,
                        payload: payload.clone(),
                        peer: Some("S→C".into()),
                    });
                    if cw.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        *a2.lock().await = false;
    });

    let _ = tokio::join!(c2s, s2c);
    Ok(())
}

impl SessionView for ProxySession {
    fn kind(&self) -> SessionKind {
        SessionKind::Proxy
    }

    fn title(&self) -> String {
        format!(
            "PROXY {} → {}",
            self.bind.display(),
            self.upstream.display()
        )
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn target_display(&self) -> String {
        format!("{} → {}", self.bind.display(), self.upstream.display())
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

    fn on_io(&mut self, event: IoEvent) {
        match event {
            IoEvent::Connected { .. } => self.status = ConnStatus::Listening,
            IoEvent::Frame {
                direction,
                payload,
                peer,
            } => {
                self.frames.push_full(direction, payload, peer, None);
                if self.follow {
                    let n = self.frames.len();
                    if n > 0 {
                        self.selected = n - 1;
                    }
                }
            }
            IoEvent::Error { message } => {
                self.status = ConnStatus::Error;
                self.status_msg = message;
            }
            IoEvent::Status { message } => self.status_msg = message,
            _ => {}
        }
    }

    fn cmd_tx(&self) -> Option<&CmdTx> {
        self.cmd_tx.as_ref()
    }

    fn status_message(&self) -> &str {
        &self.status_msg
    }
}
