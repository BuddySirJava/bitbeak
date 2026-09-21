//! Mouse hit-testing regions produced by each frame draw.

use ratatui::layout::Rect;

use crate::inspect::InspectMode;
use crate::session::{HttpField, PaneFocus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitTarget {
    Tab(usize),
    NewTab,
    Focus(PaneFocus),
    HttpField(HttpField),
    InspectMode(InspectMode),
    FooterF(u8),
    Send,
    Broadcast,
    LogRow(usize),
    HistoryRow(usize),
    QuitYes,
    QuitNo,
    NewKind(usize),
    CollectionRow(usize),
    OverlayDismiss,
}

#[derive(Debug, Default, Clone)]
pub struct HitMap {
    hits: Vec<(Rect, HitTarget)>,
}

impl HitMap {
    pub fn clear(&mut self) {
        self.hits.clear();
    }

    pub fn push(&mut self, rect: Rect, target: HitTarget) {
        if rect.width > 0 && rect.height > 0 {
            self.hits.push((rect, target));
        }
    }

    pub fn hit(&self, col: u16, row: u16) -> Option<HitTarget> {
        // Last registered wins (overlays drawn last).
        for (rect, target) in self.hits.iter().rev() {
            if col >= rect.x
                && col < rect.x.saturating_add(rect.width)
                && row >= rect.y
                && row < rect.y.saturating_add(rect.height)
            {
                return Some(*target);
            }
        }
        None
    }
}
