//! Simple HTTP mock server session.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tui_textarea::TextArea;

use crate::cli::Target;
use crate::frame::{Direction, FrameBuffer};
use crate::inspect::InspectMode;
use crate::session::{ConnStatus, PaneFocus, SessionKind, SessionView};
use crate::transport::{CmdTx, IoEvent, IoRx};
use crate::ui::textarea_util;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MockRoute {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub body: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockRouteCell {
    Method,
    Path,
    Status,
    Body,
    Latency,
}

#[derive(Serialize, Deserialize)]
struct MockRoutesFile {
    routes: Vec<MockRoute>,
}

pub fn mock_routes_path(bind: &str) -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitbeak")
        .join("mocks")
        .join(format!("{}.toml", sanitize_bind(bind)))
}

fn sanitize_bind(bind: &str) -> String {
    bind.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

pub fn load_routes(bind: &str) -> Option<Vec<MockRoute>> {
    let path = mock_routes_path(bind);
    let text = std::fs::read_to_string(&path).ok()?;
    let file: MockRoutesFile = toml::from_str(&text).ok()?;
    Some(file.routes)
}

pub fn save_routes(bind: &str, routes: &[MockRoute]) -> Result<()> {
    let path = mock_routes_path(bind);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create mock config dir")?;
    }
    let file = MockRoutesFile {
        routes: routes.to_vec(),
    };
    let text = toml::to_string_pretty(&file).context("serialize mock routes")?;
    std::fs::write(&path, text).context("write mock routes")?;
    Ok(())
}

pub fn default_routes() -> Vec<MockRoute> {
    vec![MockRoute {
        method: "GET".into(),
        path: "/".into(),
        status: 200,
        body: "ok".into(),
        latency_ms: 0,
    }]
}

pub struct MockSession {
    pub bind: String,
    pub status: ConnStatus,
    pub frames: FrameBuffer,
    pub selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub inspect: InspectMode,
    pub routes: Arc<RwLock<Vec<MockRoute>>>,
    pub route_row: usize,
    pub route_cell: MockRouteCell,
    pub route_method_ta: TextArea<'static>,
    pub route_path_ta: TextArea<'static>,
    pub route_status_ta: TextArea<'static>,
    pub route_body_ta: TextArea<'static>,
    pub route_latency_ta: TextArea<'static>,
    pub status_msg: String,
    pub io_rx: Option<IoRx>,
}

impl MockSession {
    pub fn start(bind: Target, max_frames: usize, routes: Vec<MockRoute>) -> Self {
        let (host, port) = match &bind {
            Target::Tcp { host, port } => (host.clone(), *port),
            _ => ("127.0.0.1".into(), 18080),
        };
        let addr = format!("{host}:{port}");
        let (io_tx, io_rx) = mpsc::unbounded_channel();
        let routes_arc = Arc::new(RwLock::new(routes));
        let routes_for_server = Arc::clone(&routes_arc);
        let host_c = host.clone();
        tokio::spawn(async move {
            let listener = match TcpListener::bind((host_c.as_str(), port)).await {
                Ok(l) => l,
                Err(e) => {
                    let _ = io_tx.send(IoEvent::Error {
                        message: format!("mock bind: {e}"),
                    });
                    return;
                }
            };
            let _ = io_tx.send(IoEvent::Status {
                message: format!("mock listening {host_c}:{port}"),
            });
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    continue;
                };
                let io = TokioIo::new(stream);
                let routes = Arc::clone(&routes_for_server);
                let io_tx = io_tx.clone();
                tokio::spawn(async move {
                    let peer_s = peer.to_string();
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let routes = Arc::clone(&routes);
                        let io_tx = io_tx.clone();
                        let peer_s = peer_s.clone();
                        async move {
                            let method = req.method().as_str().to_string();
                            let path = req.uri().path().to_string();
                            let _ = io_tx.send(IoEvent::Frame {
                                direction: Direction::In,
                                payload: Bytes::from(format!("{method} {path}")),
                                peer: Some(peer_s),
                            });
                            let route = {
                                let routes = routes.read().unwrap_or_else(|e| e.into_inner());
                                routes
                                    .iter()
                                    .find(|r| {
                                        (r.method == "*" || r.method.eq_ignore_ascii_case(&method))
                                            && (r.path == "*" || path.starts_with(&r.path))
                                    })
                                    .cloned()
                            };
                            if let Some(r) = route {
                                if r.latency_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(r.latency_ms)).await;
                                }
                                let status =
                                    StatusCode::from_u16(r.status).unwrap_or(StatusCode::OK);
                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(status)
                                        .header("content-type", "text/plain")
                                        .body(Full::new(Bytes::from(r.body.clone())))
                                        .unwrap(),
                                )
                            } else {
                                Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::from_static(b"no route")))
                                    .unwrap())
                            }
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        let mut s = Self {
            bind: addr,
            status: ConnStatus::Listening,
            frames: FrameBuffer::new(max_frames),
            selected: 0,
            follow: true,
            focus: PaneFocus::Log,
            inspect: InspectMode::Raw,
            routes: routes_arc,
            route_row: 0,
            route_cell: MockRouteCell::Method,
            route_method_ta: textarea_util::single_line("GET"),
            route_path_ta: textarea_util::single_line("/"),
            route_status_ta: textarea_util::single_line("200"),
            route_body_ta: textarea_util::single_line("ok"),
            route_latency_ta: textarea_util::single_line("0"),
            status_msg: "mock server starting…".into(),
            io_rx: Some(io_rx),
        };
        s.sync_route_editor_from_row();
        s
    }

    pub fn take_io_rx(&mut self) -> Option<IoRx> {
        self.io_rx.take()
    }

    pub fn routes_snapshot(&self) -> Vec<MockRoute> {
        self.routes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn sync_route_editor_from_row(&mut self) {
        let routes = self.routes_snapshot();
        if let Some(r) = routes.get(self.route_row) {
            textarea_util::set_text(&mut self.route_method_ta, &r.method);
            textarea_util::set_text(&mut self.route_path_ta, &r.path);
            textarea_util::set_text(&mut self.route_status_ta, &r.status.to_string());
            textarea_util::set_text(&mut self.route_body_ta, &r.body);
            textarea_util::set_text(&mut self.route_latency_ta, &r.latency_ms.to_string());
        } else {
            textarea_util::set_text(&mut self.route_method_ta, "");
            textarea_util::set_text(&mut self.route_path_ta, "");
            textarea_util::set_text(&mut self.route_status_ta, "");
            textarea_util::set_text(&mut self.route_body_ta, "");
            textarea_util::set_text(&mut self.route_latency_ta, "");
        }
    }

    pub fn commit_route_editor_to_row(&mut self) {
        let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
        if routes.is_empty() {
            return;
        }
        if self.route_row >= routes.len() {
            self.route_row = routes.len().saturating_sub(1);
        }
        let status = textarea_util::text_of(&self.route_status_ta)
            .parse()
            .unwrap_or(200);
        let latency = textarea_util::text_of(&self.route_latency_ta)
            .parse()
            .unwrap_or(0);
        routes[self.route_row] = MockRoute {
            method: textarea_util::text_of(&self.route_method_ta),
            path: textarea_util::text_of(&self.route_path_ta),
            status,
            body: textarea_util::text_of(&self.route_body_ta),
            latency_ms: latency,
        };
        drop(routes);
        let _ = self.persist_routes();
    }

    pub fn route_add_row(&mut self) {
        self.commit_route_editor_to_row();
        {
            let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
            routes.push(MockRoute {
                method: "GET".into(),
                path: "/".into(),
                status: 200,
                body: String::new(),
                latency_ms: 0,
            });
        }
        self.route_row = self.routes_snapshot().len().saturating_sub(1);
        self.sync_route_editor_from_row();
        self.focus = PaneFocus::Form;
        let _ = self.persist_routes();
    }

    pub fn route_delete_row(&mut self) {
        {
            let mut routes = self.routes.write().unwrap_or_else(|e| e.into_inner());
            if routes.is_empty() {
                return;
            }
            routes.remove(self.route_row);
        }
        if self.route_row > 0 && self.route_row >= self.routes_snapshot().len() {
            self.route_row -= 1;
        }
        self.sync_route_editor_from_row();
        let _ = self.persist_routes();
    }

    pub fn persist_routes(&self) -> Result<PathBuf> {
        let routes = self.routes_snapshot();
        save_routes(&self.bind, &routes)?;
        Ok(mock_routes_path(&self.bind))
    }

    pub fn active_route_textarea_mut(&mut self) -> &mut TextArea<'static> {
        match self.route_cell {
            MockRouteCell::Method => &mut self.route_method_ta,
            MockRouteCell::Path => &mut self.route_path_ta,
            MockRouteCell::Status => &mut self.route_status_ta,
            MockRouteCell::Body => &mut self.route_body_ta,
            MockRouteCell::Latency => &mut self.route_latency_ta,
        }
    }
}

impl SessionView for MockSession {
    fn kind(&self) -> SessionKind {
        SessionKind::Mock
    }
    fn title(&self) -> String {
        format!("MOCK {}", self.bind)
    }
    fn status(&self) -> ConnStatus {
        self.status
    }
    fn target_display(&self) -> String {
        self.bind.clone()
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
            IoEvent::Status { message } => {
                self.status = ConnStatus::Listening;
                self.status_msg = message;
            }
            IoEvent::Frame {
                direction,
                payload,
                peer,
            } => {
                self.frames
                    .push_full(direction, payload, peer, Some("mock".into()));
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
            _ => {}
        }
    }
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
    use tempfile::TempDir;

    #[test]
    fn mock_routes_roundtrip() {
        let dir = TempDir::new().unwrap();
        let bind = "127.0.0.1:9999";
        let path = dir.path().join("test.toml");
        let routes = vec![MockRoute {
            method: "POST".into(),
            path: "/api".into(),
            status: 201,
            body: "created".into(),
            latency_ms: 5,
        }];
        let file = MockRoutesFile {
            routes: routes.clone(),
        };
        std::fs::write(&path, toml::to_string_pretty(&file).unwrap()).unwrap();
        let loaded: MockRoutesFile =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.routes, routes);
        assert_eq!(sanitize_bind(bind), "127_0_0_1_9999");
    }
}
