//! Shared TextArea helpers.

use crossterm::event::KeyEvent;
use ratatui::style::{Modifier, Style};
use tui_textarea::TextArea;

use crate::ui::theme;

pub fn single_line(initial: &str) -> TextArea<'static> {
    let mut ta = TextArea::from(vec![initial.to_string()]);
    ta.move_cursor(tui_textarea::CursorMove::End);
    style_unfocused(&mut ta);
    ta
}

pub fn multi_line(initial: &str) -> TextArea<'static> {
    let lines: Vec<String> = if initial.is_empty() {
        vec![String::new()]
    } else {
        initial.lines().map(str::to_string).collect()
    };
    let mut ta = TextArea::from(lines);
    ta.move_cursor(tui_textarea::CursorMove::End);
    style_unfocused(&mut ta);
    ta
}

pub fn text_of(ta: &TextArea<'_>) -> String {
    ta.lines().join("\n")
}

pub fn set_text(ta: &mut TextArea<'static>, text: &str) {
    *ta = if text.contains('\n') {
        multi_line(text)
    } else {
        single_line(text)
    };
}

pub fn style_focused(ta: &mut TextArea<'_>) {
    ta.set_cursor_style(Style::default().add_modifier(Modifier::REVERSED));
    ta.set_style(theme::value());
}

pub fn style_unfocused(ta: &mut TextArea<'_>) {
    ta.set_cursor_style(Style::default());
    ta.set_style(theme::value());
}

pub fn input(ta: &mut TextArea<'_>, key: KeyEvent) {
    ta.input(key);
}
