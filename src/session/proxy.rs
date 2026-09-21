//! Local proxy / tap session (TCP splice + optional TLS intercept).

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as AnyhowContext, Result};
use bytes::{Bytes, BytesMut};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tui_textarea::TextArea;

use crate::cli::Target;
use crate::composer::ComposerMode;
use crate::frame::{Direction, FrameBuffer};
use crate::inspect::InspectMode;
use crate::session::{ConnStatus, PaneFocus, SessionKind, SessionView};
use crate::tls_mitm::{parse_sni_from_client_hello, MitmCa};
use crate::transport::{channels, CmdTx, IoCommand, IoEvent, IoRx};
use crate::ui::textarea_util;

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
    pub composer_mode: ComposerMode,
    pub composer: TextArea<'static>,
    pub io_rx: Option<IoRx>,
    pub cmd_tx: CmdTx,
    /// True while an accepted client splice is active (inject can reach upstream).
    splice_live: Arc<AtomicBool>,
    _handle: Option<tokio::task::JoinHandle<()>>,
}

impl ProxySession {
    pub fn start(bind: Target, upstream: Target, max_frames: usize, tls_intercept: bool) -> Self {
        let (io_tx, io_rx, cmd_tx, cmd_rx) = channels();
        let bind_c = bind.clone();
        let upstream_c = upstream.clone();
        let splice_live = Arc::new(AtomicBool::new(false));
        let splice_flag = Arc::clone(&splice_live);
        let status_msg = if tls_intercept {
            match MitmCa::load_or_create() {
                Ok(ca) => format!(
                    "TLS intercept (HTTP/1.1 ALPN) — CA: {} · : ca-path",
                    ca.ca_pem_path().display()
                ),
                Err(e) => format!("TLS intercept CA error: {e:#}"),
            }
        } else {
            "proxy listening…".into()
        };
        let handle = tokio::spawn(async move {
            if let Err(e) =
                run_tcp_proxy(bind_c, upstream_c, io_tx.clone(), cmd_rx, tls_intercept, splice_flag)
                    .await
            {
                let _ = io_tx.send(IoEvent::Error {
                    message: format!("proxy failed: {e:#}"),
                });
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
            status_msg,
            tls_intercept,
            composer_mode: ComposerMode::Utf8,
            composer: textarea_util::multi_line(""),
            io_rx: Some(io_rx),
            cmd_tx,
            splice_live,
            _handle: Some(handle),
        }
    }

    pub fn take_io_rx(&mut self) -> Option<IoRx> {
        self.io_rx.take()
    }

    pub fn send_composer(&mut self) {
        match crate::composer::decode_payload(
            &textarea_util::text_of(&self.composer),
            self.composer_mode,
        ) {
            Ok(payload) if !payload.is_empty() => {
                if !self.splice_live.load(Ordering::Relaxed) {
                    self.status_msg = "no active splice — wait for a client connection".into();
                    return;
                }
                let _ = self.cmd_tx.send(IoCommand::Send {
                    payload: Bytes::from(payload),
                    client_id: None,
                });
                self.status_msg = "inject queued → upstream".into();
            }
            Ok(_) => self.status_msg = "composer empty".into(),
            Err(e) => self.status_msg = format!("composer: {e}"),
        }
    }

    pub fn sync_composer_style(&mut self) {
        if self.focus == PaneFocus::Composer {
            textarea_util::style_focused(&mut self.composer);
        } else {
            textarea_util::style_unfocused(&mut self.composer);
        }
    }
}

async fn run_tcp_proxy(
    bind: Target,
    upstream: Target,
    io_tx: crate::transport::IoTx,
    mut cmd_rx: crate::transport::CmdRx,
    tls_intercept: bool,
    splice_live: Arc<AtomicBool>,
) -> Result<()> {
    let (host, port) = match &bind {
        Target::Tcp { host, port } => (host.clone(), *port),
        _ => anyhow::bail!("proxy bind must be tcp://"),
    };
    let (up_host, up_port) = match &upstream {
        Target::Tcp { host, port } => (host.clone(), *port),
        _ => anyhow::bail!("proxy upstream must be tcp://"),
    };

    let ca = if tls_intercept {
        Some(Arc::new(MitmCa::load_or_create()?))
    } else {
        None
    };

    let addr = crate::cli::join_host_port(&host, port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let _ = io_tx.send(IoEvent::Status {
        message: format!(
            "proxy {addr} → {}",
            crate::cli::join_host_port(&up_host, up_port)
        ),
    });
    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("listen:{addr}"),
    });

    // Latest active inject channel (toward upstream).
    let inject: Arc<Mutex<Option<mpsc::UnboundedSender<Bytes>>>> = Arc::new(Mutex::new(None));
    let inject_cmd = inject.clone();
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                IoCommand::Send { payload, .. } | IoCommand::Broadcast { payload } => {
                    if let Some(tx) = inject_cmd.lock().await.as_ref() {
                        let _ = tx.send(payload);
                    }
                }
                IoCommand::Close => break,
            }
        }
    });

    loop {
        let (client, peer) = listener.accept().await?;
        let io_tx2 = io_tx.clone();
        let up_host = up_host.clone();
        let ca = ca.clone();
        let inject = inject.clone();
        let splice_live = Arc::clone(&splice_live);
        tokio::spawn(async move {
            let _ = io_tx2.send(IoEvent::ClientJoined {
                id: 1,
                peer: peer.to_string(),
            });
            let (inj_tx, inj_rx) = mpsc::unbounded_channel();
            *inject.lock().await = Some(inj_tx);
            splice_live.store(true, Ordering::Relaxed);
            let result = if let Some(ca) = ca {
                mitm_splice(client, &up_host, up_port, ca, io_tx2.clone(), inj_rx).await
            } else {
                match TcpStream::connect((up_host.as_str(), up_port)).await {
                    Ok(server) => splice(client, server, io_tx2.clone(), inj_rx).await,
                    Err(e) => Err(anyhow::anyhow!("upstream connect: {e}")),
                }
            };
            splice_live.store(false, Ordering::Relaxed);
            *inject.lock().await = None;
            if let Err(e) = result {
                let _ = io_tx2.send(IoEvent::Error {
                    message: e.to_string(),
                });
            }
            let _ = io_tx2.send(IoEvent::ClientLeft { id: 1 });
        });
    }
}

/// Stream that replays a buffered prefix before reading from the inner TCP stream.
struct PrefixedTcp {
    prefix: BytesMut,
    inner: TcpStream,
}

impl AsyncRead for PrefixedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = buf.remaining().min(self.prefix.len());
            buf.put_slice(&self.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn read_client_hello(stream: &mut TcpStream) -> Result<BytesMut> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x16 {
        anyhow::bail!("expected TLS handshake record (got {:#x})", header[0]);
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    let mut out = BytesMut::with_capacity(5 + len);
    out.extend_from_slice(&header);
    out.extend_from_slice(&body);
    Ok(out)
}

async fn mitm_splice(
    mut client: TcpStream,
    up_host: &str,
    up_port: u16,
    ca: Arc<MitmCa>,
    io_tx: crate::transport::IoTx,
    inj_rx: mpsc::UnboundedReceiver<Bytes>,
) -> Result<()> {
    let hello = read_client_hello(&mut client).await?;
    let sni = parse_sni_from_client_hello(&hello).unwrap_or_else(|| up_host.to_string());
    let server_cfg = ca.mint_server_config(&sni)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let prefixed = PrefixedTcp {
        prefix: hello,
        inner: client,
    };
    let client_tls = acceptor
        .accept(prefixed)
        .await
        .context("TLS accept (install BitBeak CA in the client)")?;

    let upstream = TcpStream::connect((up_host, up_port))
        .await
        .context("upstream connect")?;
    let mut root = rustls::RootCertStore::empty();
    root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|_| anyhow::anyhow!("invalid SNI/server name: {sni}"))?;
    let server_tls = connector
        .connect(server_name, upstream)
        .await
        .context("upstream TLS")?;

    splice_any(client_tls, server_tls, io_tx, inj_rx, true).await
}

async fn splice(
    client: TcpStream,
    server: TcpStream,
    io_tx: crate::transport::IoTx,
    inj_rx: mpsc::UnboundedReceiver<Bytes>,
) -> Result<()> {
    splice_any(client, server, io_tx, inj_rx, false).await
}

async fn splice_any<C, S>(
    client: C,
    server: S,
    io_tx: crate::transport::IoTx,
    mut inj_rx: mpsc::UnboundedReceiver<Bytes>,
    http_reassemble: bool,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut sr, mut sw) = tokio::io::split(server);
    let active = Arc::new(Mutex::new(true));

    let io1 = io_tx.clone();
    let a1 = active.clone();
    let c2s = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut asm = Http1Assembler::new(true);
        loop {
            if !*a1.lock().await {
                break;
            }
            tokio::select! {
                biased;
                inj = inj_rx.recv() => {
                    let Some(payload) = inj else {
                        // Inject channel closed for this connection — ignore forever.
                        futures_util::future::pending::<()>().await;
                        break;
                    };
                    let _ = io1.send(IoEvent::Frame {
                        direction: Direction::Out,
                        payload: payload.clone(),
                        peer: Some("inject→up".into()),
                    });
                    if sw.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                read = cr.read(&mut buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            let payload = Bytes::copy_from_slice(&buf[..n]);
                            if http_reassemble {
                                for msg in asm.push(&payload) {
                                    let _ = io1.send(IoEvent::Frame {
                                        direction: Direction::Out,
                                        payload: msg.body,
                                        peer: Some(msg.tag),
                                    });
                                }
                            } else {
                                let _ = io1.send(IoEvent::Frame {
                                    direction: Direction::Out,
                                    payload: payload.clone(),
                                    peer: Some("C→S".into()),
                                });
                            }
                            if sw.write_all(&payload).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        *a1.lock().await = false;
    });

    let io2 = io_tx;
    let a2 = active;
    let s2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut asm = Http1Assembler::new(false);
        while *a2.lock().await {
            match sr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    if http_reassemble {
                        for msg in asm.push(&payload) {
                            let _ = io2.send(IoEvent::Frame {
                                direction: Direction::In,
                                payload: msg.body,
                                peer: Some(msg.tag),
                            });
                        }
                    } else {
                        let _ = io2.send(IoEvent::Frame {
                            direction: Direction::In,
                            payload: payload.clone(),
                            peer: Some("S→C".into()),
                        });
                    }
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

struct HttpMsg {
    tag: String,
    body: Bytes,
}

/// Best-effort HTTP/1.1 message boundary detection for MITM plaintext.
struct Http1Assembler {
    buf: BytesMut,
    is_request: bool,
}

impl Http1Assembler {
    fn new(is_request: bool) -> Self {
        Self {
            buf: BytesMut::new(),
            is_request,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Vec<HttpMsg> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(msg) = self.try_pop() {
            out.push(msg);
        }
        out
    }

    fn try_pop(&mut self) -> Option<HttpMsg> {
        let sep = self
            .buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .or_else(|| self.buf.windows(2).position(|w| w == b"\n\n"))?;
        let (sep_len, head_end) = if self.buf[sep..].starts_with(b"\r\n\r\n") {
            (4, sep)
        } else {
            (2, sep)
        };
        let head_bytes = self.buf[..head_end].to_vec();
        let head_str = String::from_utf8_lossy(&head_bytes).into_owned();
        let first = head_str.lines().next().unwrap_or("").trim().to_string();
        let mut content_len: Option<usize> = None;
        for line in head_str.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse().ok();
                }
            }
        }
        let body_start = head_end + sep_len;
        let body_len = content_len.unwrap_or(0);
        if self.buf.len() < body_start + body_len {
            return None;
        }
        let total = body_start + body_len;
        let frame = self.buf.split_to(total).freeze();
        let tag = if self.is_request {
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("REQ");
            let path = parts.next().unwrap_or("/");
            format!("HTTP {method} {path}")
        } else {
            format!("HTTP {first}")
        };
        let preview = if frame.len() > 4096 {
            Bytes::copy_from_slice(&frame[..4096])
        } else {
            frame
        };
        Some(HttpMsg {
            tag,
            body: preview,
        })
    }
}

impl SessionView for ProxySession {
    fn kind(&self) -> SessionKind {
        SessionKind::Proxy
    }

    fn title(&self) -> String {
        let mitm = if self.tls_intercept { " MITM" } else { "" };
        format!(
            "PROXY{mitm} {} → {}",
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
        self.sync_composer_style();
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
        Some(&self.cmd_tx)
    }

    fn status_message(&self) -> &str {
        &self.status_msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_http_request() {
        let mut a = Http1Assembler::new(true);
        let raw = b"GET /hi HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let msgs = a.push(raw);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].tag, "HTTP GET /hi");
        assert!(String::from_utf8_lossy(&msgs[0].body).contains("hello"));
        assert_eq!(&a.buf[..], b"EXTRA");
    }
}
