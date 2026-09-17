//! Envoke CLI 256-color palette for ratatui.

use ratatui::style::{Color, Modifier, Style};

pub const ORANGE: Color = Color::Indexed(208);
pub const AMBER: Color = Color::Indexed(214);
pub const TEXT: Color = Color::Indexed(253);
pub const STONE: Color = Color::Indexed(250);
pub const MUTED: Color = Color::Indexed(240);
pub const DIM: Color = Color::Indexed(245);
pub const SUCCESS: Color = Color::Indexed(114);
pub const DANGER: Color = Color::Indexed(203);
pub const CRITICAL: Color = Color::Indexed(197);
pub const BLUE: Color = Color::Indexed(117);
pub const SELECT_BG: Color = Color::Indexed(236);

pub fn border() -> Style {
    Style::default().fg(MUTED)
}

pub fn title() -> Style {
    Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
}

pub fn header() -> Style {
    Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
}

pub fn label() -> Style {
    Style::default().fg(DIM)
}

pub fn value() -> Style {
    Style::default().fg(TEXT)
}

pub fn accent() -> Style {
    Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
}

pub fn dim() -> Style {
    Style::default().fg(DIM)
}

pub fn success() -> Style {
    Style::default().fg(SUCCESS)
}

pub fn danger() -> Style {
    Style::default().fg(DANGER)
}

pub fn blue() -> Style {
    Style::default().fg(BLUE)
}

pub fn selected(base: Style) -> Style {
    base.bg(SELECT_BG)
}

pub fn dir_in() -> Style {
    Style::default().fg(BLUE)
}

pub fn dir_out() -> Style {
    Style::default().fg(ORANGE)
}

pub fn status_style(code: u16) -> Style {
    if (200..300).contains(&code) {
        success()
    } else if (300..400).contains(&code) {
        Style::default().fg(AMBER)
    } else if code >= 500 {
        Style::default().fg(CRITICAL)
    } else if code >= 400 {
        danger()
    } else {
        Style::default().fg(STONE)
    }
}

pub fn footer_key() -> Style {
    Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)
}

pub fn footer_label() -> Style {
    Style::default().fg(TEXT)
}

pub fn json_key() -> Style {
    Style::default().fg(AMBER)
}

pub fn json_string() -> Style {
    Style::default().fg(BLUE)
}

pub fn json_number() -> Style {
    Style::default().fg(SUCCESS)
}

pub fn json_literal() -> Style {
    Style::default().fg(ORANGE)
}

pub fn disabled_key() -> Style {
    Style::default().fg(MUTED)
}

pub fn disabled_label() -> Style {
    Style::default().fg(MUTED)
}

pub fn conn_status(status: crate::session::ConnStatus) -> Style {
    use crate::session::ConnStatus;
    match status {
        ConnStatus::Connected => success(),
        ConnStatus::Listening => blue(),
        ConnStatus::Disconnected | ConnStatus::Error => danger(),
        ConnStatus::Connecting => dim(),
        ConnStatus::Idle => Style::default().fg(STONE),
    }
}

pub fn toast_ok() -> Style {
    success()
}

pub fn toast_err() -> Style {
    danger()
}
