//! Multi-client listen session.

use bytes::Bytes;
use tui_textarea::TextArea;

use crate::cli::Target;
use crate::composer::ComposerMode;
use crate::frame::FrameBuffer;
use crate::framing::FramingConfig;
use crate::inspect::InspectMode;
use crate::session::{ConnStatus, PaneFocus, SessionKind, SessionView};
use crate::transport::{channels, spawn_listen, CmdTx, IoCommand, IoEvent, IoRx};
use crate::ui::textarea_util;

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub id: u64,
    pub peer: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub struct ListenSession {
    pub target: Target,
    pub framing: FramingConfig,
    pub status: ConnStatus,
    pub frames: FrameBuffer,
    pub clients: Vec<ClientInfo>,
    pub selected_client: Option<u64>,
    pub selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub inspect: InspectMode,
    pub composer_mode: ComposerMode,
    pub composer: TextArea<'static>,
    pub broadcast: bool,
    pub filter: String,
    pub status_msg: String,
    pub cmd_tx: CmdTx,
    pub io_rx: Option<IoRx>,
    _handle: Option<tokio::task::JoinHandle<()>>,
}

impl ListenSession {
    pub fn start(target: Target, framing: FramingConfig, max_frames: usize) -> Self {
        let (io_tx, io_rx, cmd_tx, cmd_rx) = channels();
        let handle = spawn_listen(target.clone(), framing.clone(), io_tx, cmd_rx);
        Self {
            target,
            framing,
            status: ConnStatus::Listening,
            frames: FrameBuffer::new(max_frames),
            clients: Vec::new(),
            selected_client: None,
            selected: 0,
            follow: true,
            focus: PaneFocus::Clients,
            inspect: InspectMode::Hex,
            composer_mode: ComposerMode::Utf8,
            composer: textarea_util::multi_line(""),
            broadcast: false,
            filter: String::new(),
            status_msg: "waiting for clients…".into(),
            cmd_tx,
            io_rx: Some(io_rx),
            _handle: Some(handle),
        }
    }

    /// UI tests — no listen socket.
    pub fn inert(target: Target, framing: FramingConfig, max_frames: usize) -> Self {
        let (_io_tx, io_rx, cmd_tx, _cmd_rx) = channels();
        Self {
            target,
            framing,
            status: ConnStatus::Listening,
            frames: FrameBuffer::new(max_frames),
            clients: Vec::new(),
            selected_client: None,
            selected: 0,
            follow: true,
            focus: PaneFocus::Composer,
            inspect: InspectMode::Hex,
            composer_mode: ComposerMode::Utf8,
            composer: textarea_util::multi_line(""),
            broadcast: false,
            filter: String::new(),
            status_msg: "waiting for clients…".into(),
            cmd_tx,
            io_rx: Some(io_rx),
            _handle: None,
        }
    }

    pub fn take_io_rx(&mut self) -> Option<IoRx> {
        self.io_rx.take()
    }

    pub fn composer_text(&self) -> String {
        textarea_util::text_of(&self.composer)
    }

    pub fn send_composer(&mut self) {
        let bytes = match crate::composer::decode_payload(&self.composer_text(), self.composer_mode)
        {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                self.status_msg = e;
                return;
            }
        };
        if self.broadcast {
            let _ = self.cmd_tx.send(IoCommand::Broadcast { payload: bytes });
        } else {
            let _ = self.cmd_tx.send(IoCommand::Send {
                payload: bytes,
                client_id: self.selected_client,
            });
        }
    }

    pub fn select_client_index(&mut self, idx: usize) {
        if let Some(c) = self.clients.get(idx) {
            self.selected_client = Some(c.id);
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

impl SessionView for ListenSession {
    fn kind(&self) -> SessionKind {
        SessionKind::Listen
    }

    fn title(&self) -> String {
        format!("LISTEN {}", self.target.display())
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn target_display(&self) -> String {
        self.target.display()
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
            IoEvent::ClientJoined { id, peer } => {
                self.clients.push(ClientInfo {
                    id,
                    peer: peer.clone(),
                    bytes_in: 0,
                    bytes_out: 0,
                });
                if self.selected_client.is_none() {
                    self.selected_client = Some(id);
                }
                self.status_msg = format!("client joined {peer}");
            }
            IoEvent::ClientLeft { id } => {
                self.clients.retain(|c| c.id != id);
                if self.selected_client == Some(id) {
                    self.selected_client = self.clients.first().map(|c| c.id);
                }
            }
            IoEvent::Frame {
                direction,
                payload,
                peer,
            } => {
                let len = payload.len() as u64;
                if let Some(p) = &peer {
                    if let Some(c) = self.clients.iter_mut().find(|c| &c.peer == p) {
                        match direction {
                            crate::frame::Direction::In => c.bytes_in += len,
                            crate::frame::Direction::Out => c.bytes_out += len,
                        }
                    }
                }
                self.frames.push_full(direction, payload, peer, None);
                if self.follow {
                    let n = self.frames.filtered(&self.filter).len();
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
            IoEvent::Disconnected { reason } => {
                self.status_msg = reason;
            }
        }
    }

    fn cmd_tx(&self) -> Option<&CmdTx> {
        Some(&self.cmd_tx)
    }

    fn status_message(&self) -> &str {
        &self.status_msg
    }
}
