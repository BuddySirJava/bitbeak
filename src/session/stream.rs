//! Stream connect session.

use bytes::Bytes;
use tui_textarea::TextArea;

use crate::cli::Target;
use crate::composer::ComposerMode;
use crate::frame::FrameBuffer;
use crate::framing::FramingConfig;
use crate::inspect::InspectMode;
use crate::session::{
    jump_bottom, move_selection, ConnStatus, PaneFocus, SessionKind, SessionView,
};
use crate::transport::{channels, spawn_connect, CmdTx, IoCommand, IoEvent, IoRx};
use crate::ui::textarea_util;

pub struct StreamSession {
    pub target: Target,
    pub framing: FramingConfig,
    pub status: ConnStatus,
    pub frames: FrameBuffer,
    pub selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub inspect: InspectMode,
    pub composer_mode: ComposerMode,
    pub composer: TextArea<'static>,
    pub filter: String,
    pub status_msg: String,
    pub cmd_tx: CmdTx,
    pub io_rx: Option<IoRx>,
    pub max_frames: usize,
    _handle: Option<tokio::task::JoinHandle<()>>,
}

impl StreamSession {
    pub fn start(target: Target, framing: FramingConfig, max_frames: usize) -> Self {
        let (io_tx, io_rx, cmd_tx, cmd_rx) = channels();
        let handle = spawn_connect(target.clone(), framing.clone(), io_tx, cmd_rx);
        Self {
            target,
            framing,
            status: ConnStatus::Connecting,
            frames: FrameBuffer::new(max_frames),
            selected: 0,
            follow: true,
            focus: PaneFocus::Log,
            inspect: InspectMode::Hex,
            composer_mode: ComposerMode::Utf8,
            composer: textarea_util::multi_line(""),
            filter: String::new(),
            status_msg: String::new(),
            cmd_tx,
            io_rx: Some(io_rx),
            max_frames,
            _handle: Some(handle),
        }
    }

    /// Session shell for UI tests — no connect task / runtime required.
    pub fn inert(target: Target, framing: FramingConfig, max_frames: usize) -> Self {
        let (_io_tx, io_rx, cmd_tx, _cmd_rx) = channels();
        Self {
            target,
            framing,
            status: ConnStatus::Idle,
            frames: FrameBuffer::new(max_frames),
            selected: 0,
            follow: true,
            focus: PaneFocus::Log,
            inspect: InspectMode::Hex,
            composer_mode: ComposerMode::Utf8,
            composer: textarea_util::multi_line(""),
            filter: String::new(),
            status_msg: String::new(),
            cmd_tx,
            io_rx: Some(io_rx),
            max_frames,
            _handle: None,
        }
    }

    pub fn take_io_rx(&mut self) -> Option<IoRx> {
        self.io_rx.take()
    }

    pub fn reconnect(&mut self) {
        let _ = self.cmd_tx.send(IoCommand::Close);
        let (io_tx, io_rx, cmd_tx, cmd_rx) = channels();
        let handle = spawn_connect(self.target.clone(), self.framing.clone(), io_tx, cmd_rx);
        self.cmd_tx = cmd_tx;
        self.io_rx = Some(io_rx);
        self._handle = Some(handle);
        self.status = ConnStatus::Connecting;
        self.status_msg = "reconnecting…".into();
    }

    pub fn send_bytes(&mut self, payload: Bytes) {
        let _ = self.cmd_tx.send(IoCommand::Send {
            payload,
            client_id: None,
        });
    }

    pub fn replay_selected(&mut self) {
        let filtered = self.frames.filtered(&self.filter);
        if let Some(frame) = filtered.get(self.selected) {
            let payload = frame.payload.clone();
            self.send_bytes(payload);
        }
    }

    pub fn load_selected_to_composer(&mut self) {
        let filtered = self.frames.filtered(&self.filter);
        if let Some(frame) = filtered.get(self.selected) {
            let text = crate::composer::encode_for_edit(&frame.payload, self.composer_mode);
            textarea_util::set_text(&mut self.composer, &text);
            self.focus = PaneFocus::Composer;
            textarea_util::style_focused(&mut self.composer);
        }
    }

    pub fn composer_text(&self) -> String {
        textarea_util::text_of(&self.composer)
    }

    pub fn send_composer(&mut self) {
        match crate::composer::decode_payload(&self.composer_text(), self.composer_mode) {
            Ok(bytes) => self.send_bytes(Bytes::from(bytes)),
            Err(e) => self.status_msg = e,
        }
    }

    pub fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            PaneFocus::Log => PaneFocus::Inspector,
            PaneFocus::Inspector => PaneFocus::Composer,
            _ => PaneFocus::Log,
        };
        self.sync_composer_style();
    }

    pub fn sync_composer_style(&mut self) {
        if self.focus == PaneFocus::Composer {
            textarea_util::style_focused(&mut self.composer);
        } else {
            textarea_util::style_unfocused(&mut self.composer);
        }
    }

    pub fn nav_up(&mut self) {
        let len = self.frames.filtered(&self.filter).len();
        move_selection(&mut self.selected, &mut self.follow, len, -1);
    }

    pub fn nav_down(&mut self) {
        let len = self.frames.filtered(&self.filter).len();
        move_selection(&mut self.selected, &mut self.follow, len, 1);
    }

    pub fn nav_top(&mut self) {
        crate::session::jump_top(&mut self.selected, &mut self.follow);
    }

    pub fn nav_bottom(&mut self) {
        let len = self.frames.filtered(&self.filter).len();
        jump_bottom(&mut self.selected, &mut self.follow, len);
    }
}

impl SessionView for StreamSession {
    fn kind(&self) -> SessionKind {
        SessionKind::Stream
    }

    fn title(&self) -> String {
        format!("STREAM {}", self.target.display())
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
            IoEvent::Connected { peer } => {
                self.status = ConnStatus::Connected;
                self.status_msg = format!("connected to {peer}");
            }
            IoEvent::Disconnected { reason } => {
                self.status = ConnStatus::Disconnected;
                self.status_msg = format!("disconnected: {reason} — F6 reconnect");
            }
            IoEvent::Frame {
                direction,
                payload,
                peer,
            } => {
                self.frames.push_full(direction, payload, peer, None);
                if self.follow {
                    let len = self.frames.filtered(&self.filter).len();
                    if len > 0 {
                        self.selected = len - 1;
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
