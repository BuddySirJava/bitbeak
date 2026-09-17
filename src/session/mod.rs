//! Session kinds: stream, http, listen, proxy, diagnose, capture.

mod capture;
mod diag;
mod http_session;
mod listen;
mod mock;
mod proxy;
mod stream;

pub use capture::CaptureSession;
pub use diag::DiagSession;
pub use http_session::{FormCell, HttpField, HttpSession, ResponseLineKind};
pub use listen::ListenSession;
pub use mock::{default_routes, load_routes, MockRoute, MockRouteCell, MockSession};
pub use proxy::ProxySession;
pub use stream::StreamSession;

use crate::frame::FrameBuffer;
use crate::inspect::InspectMode;
use crate::transport::{CmdTx, IoEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    Stream,
    Http,
    Listen,
    Proxy,
    Diag,
    Capture,
    Mock,
}

impl SessionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stream => "STREAM",
            Self::Http => "HTTP",
            Self::Listen => "LISTEN",
            Self::Proxy => "PROXY",
            Self::Diag => "DIAG",
            Self::Capture => "CAPTURE",
            Self::Mock => "MOCK",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnStatus {
    #[default]
    Idle,
    Connecting,
    Connected,
    Listening,
    Disconnected,
    Error,
}

impl ConnStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Connecting => "CONNECTING",
            Self::Connected => "CONNECTED",
            Self::Listening => "LISTENING",
            Self::Disconnected => "DISCONNECTED",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaneFocus {
    #[default]
    Log,
    Inspector,
    Composer,
    Clients,
    Form,
    Tree,
    Hex,
    History,
}

pub trait SessionView {
    fn kind(&self) -> SessionKind;
    fn title(&self) -> String;
    fn status(&self) -> ConnStatus;
    fn target_display(&self) -> String;
    fn frames(&self) -> &FrameBuffer;
    fn frames_mut(&mut self) -> &mut FrameBuffer;
    fn inspect_mode(&self) -> InspectMode;
    fn set_inspect_mode(&mut self, mode: InspectMode);
    fn selected_index(&self) -> usize;
    fn set_selected_index(&mut self, idx: usize);
    fn follow(&self) -> bool;
    fn set_follow(&mut self, follow: bool);
    fn focus(&self) -> PaneFocus;
    fn set_focus(&mut self, focus: PaneFocus);
    fn on_io(&mut self, event: IoEvent);
    fn cmd_tx(&self) -> Option<&CmdTx>;
    fn status_message(&self) -> &str;
}

/// Shared selection helpers for log panes.
pub fn move_selection(selected: &mut usize, follow: &mut bool, len: usize, delta: isize) {
    if len == 0 {
        *selected = 0;
        return;
    }
    let cur = (*selected).min(len - 1);
    let next = if delta < 0 {
        cur.saturating_sub((-delta) as usize)
    } else {
        (cur + delta as usize).min(len - 1)
    };
    *selected = next;
    *follow = next + 1 >= len;
}

pub fn jump_top(selected: &mut usize, follow: &mut bool) {
    *selected = 0;
    *follow = false;
}

pub fn jump_bottom(selected: &mut usize, follow: &mut bool, len: usize) {
    if len == 0 {
        *selected = 0;
        *follow = true;
        return;
    }
    *selected = len - 1;
    *follow = true;
}
