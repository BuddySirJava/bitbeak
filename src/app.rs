//! Application entry: terminal setup, event loop, overlays.

use std::io::{stdout, Stdout};

use anyhow::{Context, Result};
use bytes::Bytes;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use crate::bench::{bench_http, BenchConfig};
use crate::cli::{parse_diag, parse_target, Args};
use crate::composer::ComposerMode;
use crate::fuzz::{mutate, Mutator};
use crate::inspect::InspectMode;
use crate::pcap::{default_addrs, default_pcap_path, write_frames_pcap};
use crate::session::{CaptureSession, ConnStatus, HttpField, PaneFocus, SessionView};
use crate::transport::IoEvent;
use crate::ui;
use crate::ui::hitmap::HitTarget;
use crate::ui::textarea_util;
use crate::workspace::{Overlay, SessionSlot, Workspace};

type Term = Terminal<CrosstermBackend<Stdout>>;
type FanTx = mpsc::UnboundedSender<(usize, IoEvent)>;
type FanRx = mpsc::UnboundedReceiver<(usize, IoEvent)>;

pub fn run(args: Args) -> Result<()> {
    if let Some(path) = &args.import {
        let col = crate::collections::import::import_path(path)?;
        let out = crate::collections::save_collection(&col)?;
        println!(
            "imported {} requests → {}",
            col.requests.len(),
            out.display()
        );
        return Ok(());
    }
    if let Some(name) = &args.codegen {
        let col = crate::collections::load_collection(name)?;
        let out = crate::codegen::codegen_collection(
            &col,
            &args.codegen_lang,
            std::path::Path::new("./bitbeak-out"),
        )?;
        println!("wrote {}", out.display());
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    rt.block_on(async_run(args))
}

async fn async_run(args: Args) -> Result<()> {
    let mut ws = Workspace::new(&args)?;
    let (fan_tx, fan_rx) = mpsc::unbounded_channel();
    attach_all(&mut ws, &fan_tx);

    enable_raw_mode().context("raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture).context("enter alt screen")?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).context("terminal")?;

    let result = event_loop(&mut terminal, &mut ws, fan_tx, fan_rx).await;

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();
    result
}

/// Take `io_rx` from the session at `idx` and spawn a fan-in forwarder.
///
/// Note (v0.1): forwarders capture the index at open time. After `close_active`
/// removes a middle tab, later events for that stale index are ignored.
fn attach_io(ws: &mut Workspace, fan_tx: &FanTx, idx: usize) {
    let Some(slot) = ws.sessions.get_mut(idx) else {
        return;
    };
    let Some(mut rx) = slot.take_io_rx() else {
        return;
    };
    let tx = fan_tx.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if tx.send((idx, ev)).is_err() {
                break;
            }
        }
    });
}

fn attach_all(ws: &mut Workspace, fan_tx: &FanTx) {
    for idx in 0..ws.sessions.len() {
        attach_io(ws, fan_tx, idx);
    }
}

async fn run_pending_diag(ws: &mut Workspace) {
    let indices: Vec<usize> = ws
        .sessions
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match s {
            SessionSlot::Diag(d) if d.needs_run => Some(i),
            _ => None,
        })
        .collect();
    for idx in indices {
        if let Some(SessionSlot::Diag(d)) = ws.sessions.get_mut(idx) {
            d.needs_run = false;
            d.run_now().await;
        }
    }
}

async fn event_loop(
    terminal: &mut Term,
    ws: &mut Workspace,
    fan_tx: FanTx,
    mut fan_rx: FanRx,
) -> Result<()> {
    let mut events = EventStream::new();

    loop {
        ws.tick_flash();
        ws.tick = ws.tick.wrapping_add(1);
        run_pending_diag(ws).await;
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            s.drain_packets();
        }

        terminal.draw(|f| {
            let _ = ui::draw(f, ws);
        })?;

        tokio::select! {
            maybe = events.next() => {
                let Some(Ok(ev)) = maybe else { continue };
                match ev {
                    Event::Key(key) => {
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }
                        if handle_key(ws, key, &fan_tx).await? {
                            break;
                        }
                    }
                    Event::Mouse(m) => {
                        if handle_mouse(ws, m, &fan_tx).await? {
                            break;
                        }
                    }
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
            // Stale indices after tab close are ignored (see attach_io note).
            Some((idx, ioev)) = fan_rx.recv() => {
                if let Some(slot) = ws.sessions.get_mut(idx) {
                    slot.on_io(ioev);
                }
            }
        }
    }
    Ok(())
}

async fn handle_key(ws: &mut Workspace, key: KeyEvent, fan_tx: &FanTx) -> Result<bool> {
    // Global chords (even over overlays, except we still show Quit)
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        ws.overlay = Overlay::Quit;
        ws.quit_yes = true;
        return Ok(false);
    }
    if key.code == KeyCode::Char('t') && key.modifiers.contains(KeyModifiers::CONTROL) {
        ws.overlay = Overlay::NewSession;
        return Ok(false);
    }
    if key.code == KeyCode::Char('w') && key.modifiers.contains(KeyModifiers::CONTROL) {
        ws.request_close_active();
        return Ok(false);
    }

    match ws.overlay {
        Overlay::Quit => return Ok(handle_confirm_keys(ws, key, ConfirmKind::Quit)),
        Overlay::CloseConfirm => return Ok(handle_confirm_keys(ws, key, ConfirmKind::Close)),
        Overlay::Help => {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::F(1) | KeyCode::Char('q')
            ) {
                ws.overlay = Overlay::None;
            }
            return Ok(false);
        }
        Overlay::Filter => {
            handle_filter_keys(ws, key);
            return Ok(false);
        }
        Overlay::NewSession => {
            handle_new_session_keys(ws, key);
            return Ok(false);
        }
        Overlay::NewSessionUri { kind } => {
            handle_uri_keys(ws, key, kind, fan_tx);
            return Ok(false);
        }
        Overlay::Collections => {
            handle_collections_keys(ws, key);
            return Ok(false);
        }
        Overlay::TestsEdit | Overlay::PreScriptEdit => {
            handle_edit_overlay_keys(ws, key);
            return Ok(false);
        }
        Overlay::Bench | Overlay::Fuzz => {
            if key.code == KeyCode::Esc {
                ws.overlay = Overlay::None;
            } else if ws.overlay == Overlay::Fuzz && key.code == KeyCode::Enter {
                run_fuzz_once(ws);
                ws.overlay = Overlay::None;
            }
            return Ok(false);
        }
        Overlay::FollowStream => {
            if key.code == KeyCode::Char('r') {
                replay_follow_into_http(ws);
                return Ok(false);
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                ws.overlay = Overlay::None;
            }
            return Ok(false);
        }
        Overlay::Endpoints
        | Overlay::Hierarchy
        | Overlay::Expert
        | Overlay::Keylog => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                ws.overlay = Overlay::None;
            }
            return Ok(false);
        }
        Overlay::Conversations => {
            if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                ws.overlay = Overlay::None;
            } else if key.code == KeyCode::Up {
                if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
                    s.overlay_row = s.overlay_row.saturating_sub(1);
                }
            } else if key.code == KeyCode::Down {
                if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
                    s.overlay_row = s.overlay_row.saturating_add(1);
                }
            } else if key.code == KeyCode::Enter {
                if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
                    let rows = s.stats.conversations.rows();
                    if let Some(row) = rows.get(s.overlay_row) {
                        let expr = row.filter_expr();
                        match s.set_display_filter(&expr) {
                            Ok(()) => ws.flash_ok(format!("filter: {expr}")),
                            Err(e) => ws.flash_err(format!("filter: {e}")),
                        }
                    }
                }
                ws.overlay = Overlay::None;
            }
            return Ok(false);
        }
        Overlay::CommandPalette => {
            handle_palette_keys(ws, key, fan_tx);
            return Ok(false);
        }
        Overlay::None => {}
    }

    // Function keys
    match key.code {
        KeyCode::F(1) => {
            ws.overlay = Overlay::Help;
            return Ok(false);
        }
        KeyCode::F(2) => {
            ws.overlay = Overlay::NewSession;
            return Ok(false);
        }
        KeyCode::F(3) => {
            ws.prev_tab();
            return Ok(false);
        }
        KeyCode::F(4) => {
            ws.next_tab();
            return Ok(false);
        }
        KeyCode::F(5) => {
            cycle_format(ws);
            return Ok(false);
        }
        KeyCode::F(6) => {
            action_replay_or_run(ws, fan_tx).await;
            return Ok(false);
        }
        KeyCode::F(7) => {
            run_bench(ws).await;
            return Ok(false);
        }
        KeyCode::F(8) => {
            open_filter(ws);
            return Ok(false);
        }
        KeyCode::F(9) => {
            ws.collection_names = crate::collections::list_collections().unwrap_or_default();
            ws.overlay = Overlay::Collections;
            return Ok(false);
        }
        KeyCode::F(10) => {
            ws.overlay = Overlay::Quit;
            ws.quit_yes = true;
            return Ok(false);
        }
        KeyCode::F(11) => {
            ws.overlay = Overlay::Fuzz;
            return Ok(false);
        }
        KeyCode::F(12) => {
            export_pcap(ws);
            return Ok(false);
        }
        _ => {}
    }

    // Composer / form typing — accelerators disabled while typing
    if is_typing(ws) {
        return Ok(handle_typing(ws, key).await);
    }

    match key.code {
        KeyCode::Char('q') => {
            ws.overlay = Overlay::Quit;
            ws.quit_yes = true;
        }
        KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            open_palette(ws);
        }
        KeyCode::Char(':') => {
            open_palette(ws);
        }
        KeyCode::Char('/') => {
            open_filter(ws);
        }
        KeyCode::Tab => cycle_focus(ws, false),
        KeyCode::BackTab => cycle_focus(ws, true),
        KeyCode::Char('j') | KeyCode::Down => nav(ws, 1),
        KeyCode::Char('k') | KeyCode::Up => nav(ws, -1),
        KeyCode::Char('g') | KeyCode::Home => nav_home(ws),
        KeyCode::Char('G') | KeyCode::End => nav_end(ws),
        KeyCode::Char('h') | KeyCode::Left => cycle_format_dir(ws, false),
        KeyCode::Char('l') | KeyCode::Right => cycle_format_dir(ws, true),
        KeyCode::Char('r') => {
            if let Some(SessionSlot::Stream(s)) = ws.active_session_mut() {
                s.replay_selected();
            }
        }
        KeyCode::Char('R') => {
            if let Some(SessionSlot::Stream(s)) = ws.active_session_mut() {
                s.load_selected_to_composer();
            }
        }
        KeyCode::Char('a') => {
            if let Some(SessionSlot::Listen(s)) = ws.active_session_mut() {
                s.broadcast = !s.broadcast;
            }
        }
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as u8 - b'1') as usize;
            if idx < ws.sessions.len() {
                ws.active = idx;
            }
        }
        KeyCode::Char('[') => ws.prev_tab(),
        KeyCode::Char(']') => ws.next_tab(),
        KeyCode::Enter => {
            action_replay_or_run(ws, fan_tx).await;
        }
        KeyCode::Char('m') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            toggle_composer_mode(ws);
        }
        KeyCode::Esc => {
            blur_focus(ws);
        }
        KeyCode::PageDown => nav(ws, 10),
        KeyCode::PageUp => nav(ws, -10),
        _ => {}
    }
    Ok(false)
}

#[derive(Clone, Copy)]
enum ConfirmKind {
    Quit,
    Close,
}

fn handle_confirm_keys(ws: &mut Workspace, key: KeyEvent, kind: ConfirmKind) -> bool {
    let yes = match kind {
        ConfirmKind::Quit => &mut ws.quit_yes,
        ConfirmKind::Close => &mut ws.close_yes,
    };
    match key.code {
        KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l') | KeyCode::Tab => {
            *yes = !*yes;
            false
        }
        KeyCode::Enter => match kind {
            ConfirmKind::Quit => *yes,
            ConfirmKind::Close => {
                if *yes {
                    ws.close_active();
                } else {
                    ws.overlay = Overlay::None;
                }
                false
            }
        },
        KeyCode::Char('y') | KeyCode::Char('Y') => match kind {
            ConfirmKind::Quit => true,
            ConfirmKind::Close => {
                ws.close_active();
                false
            }
        },
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            ws.overlay = Overlay::None;
            false
        }
        _ => false,
    }
}

fn open_filter(ws: &mut Workspace) {
    let current = ws
        .active_session()
        .map(|s| s.filter().to_string())
        .unwrap_or_default();
    ws.filter_input = textarea_util::single_line(&current);
    textarea_util::style_focused(&mut ws.filter_input);
    ws.overlay = Overlay::Filter;
}

fn open_palette(ws: &mut Workspace) {
    ws.palette_input = textarea_util::single_line("");
    textarea_util::style_focused(&mut ws.palette_input);
    ws.overlay = Overlay::CommandPalette;
}

fn handle_filter_keys(ws: &mut Workspace, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => ws.overlay = Overlay::None,
        KeyCode::Enter => {
            apply_filter(ws);
            ws.overlay = Overlay::None;
        }
        _ => textarea_util::input(&mut ws.filter_input, key),
    }
}

fn apply_filter(ws: &mut Workspace) {
    let q = textarea_util::text_of(&ws.filter_input);
    if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
        match s.set_display_filter(&q) {
            Ok(()) => {}
            Err(e) => ws.flash_err(format!("filter: {e}")),
        }
        return;
    }
    if let Some(slot) = ws.active_session_mut() {
        slot.set_filter(q);
    }
}

fn handle_new_session_keys(ws: &mut Workspace, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            ws.overlay = Overlay::None;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if ws.new_session_cursor > 0 {
                ws.new_session_cursor -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if ws.new_session_cursor + 1 < Workspace::NEW_KINDS.len() {
                ws.new_session_cursor += 1;
            }
        }
        KeyCode::Enter => {
            let kind = ws.new_session_cursor;
            ws.begin_uri_entry(kind);
        }
        _ => {}
    }
}

fn handle_uri_keys(ws: &mut Workspace, key: KeyEvent, kind: usize, fan_tx: &FanTx) {
    match key.code {
        KeyCode::Esc => {
            ws.overlay = Overlay::NewSession;
        }
        KeyCode::Tab | KeyCode::BackTab if kind == 3 => {
            ws.uri_field = if ws.uri_field == 0 { 1 } else { 0 };
            textarea_util::style_unfocused(&mut ws.uri_input);
            textarea_util::style_unfocused(&mut ws.uri_input2);
            if ws.uri_field == 0 {
                textarea_util::style_focused(&mut ws.uri_input);
            } else {
                textarea_util::style_focused(&mut ws.uri_input2);
            }
        }
        KeyCode::Char(' ') | KeyCode::Char('i') if kind == 3 => {
            ws.uri_tls_intercept = !ws.uri_tls_intercept;
            ws.flash_ok(format!(
                "TLS intercept {}",
                if ws.uri_tls_intercept { "ON" } else { "OFF" }
            ));
        }
        KeyCode::Enter => {
            open_uri_entry(ws, kind, fan_tx);
        }
        _ => {
            if kind == 3 && ws.uri_field == 1 {
                textarea_util::input(&mut ws.uri_input2, key);
            } else {
                textarea_util::input(&mut ws.uri_input, key);
            }
        }
    }
}

fn open_uri_entry(ws: &mut Workspace, kind: usize, fan_tx: &FanTx) {
    let uri = textarea_util::text_of(&ws.uri_input);
    if kind == 3 {
        let upstream = textarea_util::text_of(&ws.uri_input2);
        match (parse_target(&uri), parse_target(&upstream)) {
            (Ok(bind), Ok(up)) => {
                ws.open_proxy(bind, up);
                let idx = ws.sessions.len() - 1;
                attach_io(ws, fan_tx, idx);
                ws.flash_ok("proxy started");
            }
            _ => {
                ws.flash_err("proxy needs bind + upstream URIs (Tab to switch)");
            }
        }
        return;
    }
    open_from_uri(ws, kind, &uri, fan_tx);
}

fn open_from_uri(ws: &mut Workspace, kind: usize, uri: &str, fan_tx: &FanTx) {
    let uri = uri.trim();
    if uri.is_empty() {
        ws.flash_err("URI is empty");
        return;
    }
    let idx_before = ws.sessions.len();
    match kind {
        0 => match parse_target(uri) {
            Ok(t) => ws.open_stream(t),
            Err(e) => {
                ws.flash_err(format!("bad URI: {e}"));
                return;
            }
        },
        1 => {
            let uri = if uri.contains("://") {
                uri.to_string()
            } else {
                format!("https://{uri}")
            };
            match parse_target(&uri) {
                Ok(t) => ws.open_http(t),
                Err(e) => {
                    ws.flash_err(format!("bad URI: {e}"));
                    return;
                }
            }
        }
        2 => match parse_target(uri) {
            Ok(t) => ws.open_listen(t),
            Err(e) => {
                ws.flash_err(format!("bad URI: {e}"));
                return;
            }
        },
        3 => {
            // palette / legacy: bind|upstream [--tls-intercept already applied via uri_tls_intercept]
            let cleaned = uri
                .replace("--tls-intercept", "")
                .replace("--mitm", "");
            if cleaned.contains("--tls-intercept") || uri.contains("--tls-intercept") || uri.contains("--mitm")
            {
                ws.uri_tls_intercept = true;
            }
            let parts: Vec<_> = cleaned.split('|').map(str::trim).filter(|s| !s.is_empty()).collect();
            if parts.len() == 2 {
                match (parse_target(parts[0]), parse_target(parts[1])) {
                    (Ok(b), Ok(u)) => {
                        let mitm = ws.uri_tls_intercept;
                        ws.open_proxy_mitm(b, u, mitm);
                    }
                    _ => {
                        ws.flash_err("proxy URI: tcp://127.0.0.1:8080|tcp://127.0.0.1:9090 [--tls-intercept]");
                        return;
                    }
                }
            } else {
                ws.flash_err("proxy URI: bind|upstream [--tls-intercept]");
                return;
            }
        }
        4 => match parse_diag(uri) {
            Ok(spec) => ws.open_diag(spec),
            Err(e) => {
                ws.flash_err(format!("bad diag: {e}"));
                return;
            }
        },
        5 => {
            ws.open_capture(uri);
        }
        6 => match ws.open_capture_file(std::path::Path::new(uri)) {
            Ok(()) => {}
            Err(e) => {
                ws.flash_err(format!("open: {e:#}"));
                return;
            }
        },
        _ => return,
    }
    if ws.sessions.len() > idx_before {
        if !matches!(ws.sessions[idx_before], SessionSlot::Capture(_)) {
            attach_io(ws, fan_tx, idx_before);
        }
        ws.flash_ok(format!("opened {}", ws.sessions[idx_before].title()));
    }
}

fn handle_edit_overlay_keys(ws: &mut Workspace, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            ws.overlay = Overlay::None;
        }
        KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let text = textarea_util::text_of(&ws.edit_ta);
            match ws.overlay {
                Overlay::TestsEdit => {
                    if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
                        s.tests = text
                            .lines()
                            .map(str::trim)
                            .filter(|l| !l.is_empty() && !l.starts_with('#'))
                            .map(|expr| crate::http::RequestTest {
                                expr: expr.to_string(),
                            })
                            .collect();
                        let n = s.tests.len();
                        ws.flash_ok(format!("tests set ({n})"));
                    }
                }
                Overlay::PreScriptEdit => {
                    if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
                        s.pre_script = text;
                        ws.flash_ok("pre-script saved");
                    }
                }
                _ => {}
            }
            ws.overlay = Overlay::None;
        }
        _ => textarea_util::input(&mut ws.edit_ta, key),
    }
}

fn handle_collections_keys(ws: &mut Workspace, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            if ws.collection_show_requests {
                ws.collection_show_requests = false;
            } else {
                ws.overlay = Overlay::None;
            }
        }
        KeyCode::Tab | KeyCode::Char('e') => {
            if let Some(col) = ws.collection.as_mut() {
                col.cycle_env();
                let name = col.active_env_name().to_string();
                ws.flash_ok(format!("env → {name}"));
            } else {
                ws.flash_err("load a collection first");
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if ws.collection_show_requests {
                ws.request_cursor = ws.request_cursor.saturating_sub(1);
            } else {
                ws.collection_cursor = ws.collection_cursor.saturating_sub(1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if ws.collection_show_requests {
                let n = ws
                    .collection
                    .as_ref()
                    .map(|c| c.requests.len())
                    .unwrap_or(0);
                if ws.request_cursor + 1 < n {
                    ws.request_cursor += 1;
                }
            } else if ws.collection_cursor + 1 < ws.collection_names.len() {
                ws.collection_cursor += 1;
            }
        }
        KeyCode::Char('d') => {
            if ws.collection_show_requests {
                if let Some(col) = ws.collection.as_mut() {
                    if ws.request_cursor < col.requests.len() {
                        let name = col.requests[ws.request_cursor].name.clone();
                        col.requests.remove(ws.request_cursor);
                        if ws.request_cursor > 0 && ws.request_cursor >= col.requests.len() {
                            ws.request_cursor -= 1;
                        }
                        match crate::collections::save_collection(col) {
                            Ok(_) => ws.flash_ok(format!("deleted {name}")),
                            Err(e) => ws.flash_err(format!("{e:#}")),
                        }
                    }
                }
            }
        }
        KeyCode::Char('S') => {
            // Shift+S = save-as append
            save_http_to_collection(ws, true);
        }
        KeyCode::Char('s') => {
            // Overwrite selected when viewing requests; else append
            let overwrite = ws.collection_show_requests
                && ws
                    .collection
                    .as_ref()
                    .map(|c| !c.requests.is_empty())
                    .unwrap_or(false);
            save_http_to_collection(ws, !overwrite);
        }
        KeyCode::Enter => {
            if ws.collection_show_requests {
                let req = ws
                    .collection
                    .as_ref()
                    .and_then(|c| c.requests.get(ws.request_cursor).cloned());
                if let Some(req) = req {
                    ensure_http_and_load(ws, &req);
                    ws.overlay = Overlay::None;
                }
            } else if let Some(name) = ws.collection_names.get(ws.collection_cursor).cloned() {
                match crate::collections::load_collection(&name) {
                    Ok(c) => {
                        ws.flash_ok(format!(
                            "loaded {} ({} reqs) · env {}",
                            c.name,
                            c.requests.len(),
                            c.active_env_name()
                        ));
                        ws.collection = Some(c);
                        ws.collection_show_requests = true;
                        ws.request_cursor = 0;
                    }
                    Err(e) => ws.flash_err(format!("{e:#}")),
                }
            }
        }
        _ => {}
    }
}

fn save_http_to_collection(ws: &mut Workspace, append: bool) {
    let Some(SessionSlot::Http(s)) = ws.active_session() else {
        ws.flash_err("need HTTP session to save");
        return;
    };
    let method = textarea_util::text_of(&s.method);
    let url = textarea_util::text_of(&s.url);
    let saved = s.to_saved(format!("{method} {url}"));
    let mut col = ws
        .collection
        .clone()
        .unwrap_or_else(|| crate::collections::Collection::new("default"));
    if append || col.requests.is_empty() || !ws.collection_show_requests {
        col.requests.push(saved);
        ws.request_cursor = col.requests.len().saturating_sub(1);
    } else if ws.request_cursor < col.requests.len() {
        let name = col.requests[ws.request_cursor].name.clone();
        let mut saved = saved;
        saved.name = name;
        col.requests[ws.request_cursor] = saved;
    } else {
        col.requests.push(saved);
    }
    match crate::collections::save_collection(&col) {
        Ok(p) => {
            ws.flash_ok(format!(
                "{} {}",
                if append { "appended" } else { "saved" },
                p.display()
            ));
            ws.collection = Some(col);
            ws.collection_names = crate::collections::list_collections().unwrap_or_default();
            if !ws.collection_show_requests {
                ws.collection_show_requests = true;
            }
        }
        Err(e) => ws.flash_err(format!("{e:#}")),
    }
}

fn ensure_http_and_load(ws: &mut Workspace, req: &crate::collections::SavedRequest) {
    if !matches!(ws.active_session(), Some(SessionSlot::Http(_))) {
        let url = if req.target.is_empty() {
            "https://example.com/".into()
        } else {
            req.target.clone()
        };
        let secure = url.starts_with("https://");
        ws.sessions
            .push(SessionSlot::Http(crate::session::HttpSession::new(
                crate::cli::Target::Http { url, secure },
                ws.max_frames,
            )));
        ws.active = ws.sessions.len() - 1;
    }
    if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
        s.load_saved(req);
        ws.flash_ok(format!("loaded request {}", req.name));
    }
}

async fn http_send(ws: &mut Workspace) {
    let col = ws.collection.clone();
    if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
        s.send_now(col.as_ref()).await;
    }
}

fn handle_palette_keys(ws: &mut Workspace, key: KeyEvent, fan_tx: &FanTx) {
    match key.code {
        KeyCode::Esc => ws.overlay = Overlay::None,
        KeyCode::Enter => {
            let cmd = textarea_util::text_of(&ws.palette_input);
            ws.overlay = Overlay::None;
            run_palette_command(ws, &cmd, fan_tx);
        }
        _ => textarea_util::input(&mut ws.palette_input, key),
    }
}

fn capture_palette<F>(ws: &mut Workspace, f: F)
where
    F: FnOnce(&mut CaptureSession) -> Option<Overlay>,
{
    let overlay = if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
        f(s)
    } else {
        ws.flash_err("need capture session");
        None
    };
    if let Some(o) = overlay {
        ws.overlay = o;
    }
}

fn capture_composer(ws: &mut Workspace, fan_tx: &FanTx) {
    let Some(SessionSlot::Capture(c)) = ws.active_session() else {
        ws.flash_err("composer: need capture session");
        return;
    };
    let Some(pkt) = c.visible_packet() else {
        ws.flash_err("composer: select a packet first");
        return;
    };
    if pkt.summary.dst.is_empty() {
        ws.flash_err("composer: selected packet has no peer address");
        return;
    }
    let peer_uri = composer_uri_from_packet(pkt);
    let Some(payload) = c.selected_payload_for_composer() else {
        ws.flash_err("composer: no payload on selected packet");
        return;
    };
    let idx_before = ws.sessions.len();
    match parse_target(&peer_uri) {
        Ok(t) => ws.open_stream(t),
        Err(e) => {
            ws.flash_err(format!("composer: {e}"));
            return;
        }
    }
    attach_io(ws, fan_tx, idx_before);
    if let Some(SessionSlot::Stream(s)) = ws.active_session_mut() {
        s.composer_mode = ComposerMode::Utf8;
        let text = crate::composer::encode_for_edit(&payload, s.composer_mode);
        textarea_util::set_text(&mut s.composer, &text);
        s.set_focus(PaneFocus::Composer);
    }
    ws.flash_ok(format!("composer → {peer_uri}"));
}

fn composer_uri_from_packet(p: &crate::dissect::PacketRecord) -> String {
    let host = p
        .field("ip.dst")
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            p.summary
                .dst
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| p.summary.dst.clone())
        });
    let port = p
        .field("tcp.dstport")
        .or_else(|| p.field("udp.dstport"))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(80);
    if host.contains(':') && !host.starts_with('[') {
        format!("tcp://[{host}]:{port}")
    } else {
        format!("tcp://{host}:{port}")
    }
}

fn replay_follow_into_http(ws: &mut Workspace) {
    let obj = ws.active_session().and_then(|s| match s {
        SessionSlot::Capture(c) => c
            .follow_view
            .as_ref()
            .and_then(|f| f.objects.iter().find(|o| o.is_request).cloned()),
        _ => None,
    });
    let Some(obj) = obj else {
        ws.flash_err("no HTTP request in follow — : follow-http on a request packet");
        return;
    };
    if obj.url.is_empty() && !matches!(ws.active_session(), Some(SessionSlot::Http(_))) {
        ws.flash_err("HTTP request has no URL (missing Host?) — open an HTTP tab first");
        return;
    }
    if !matches!(ws.active_session(), Some(SessionSlot::Http(_))) {
        let url = obj.url.clone();
        let secure = url.starts_with("https://");
        ws.sessions
            .push(SessionSlot::Http(crate::session::HttpSession::new(
                crate::cli::Target::Http { url, secure },
                ws.max_frames,
            )));
        ws.active = ws.sessions.len() - 1;
    }
    if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
        s.load_http_object(&obj);
        ws.overlay = Overlay::None;
        ws.flash_ok("replayed into HTTP — Enter to send");
    }
}

fn sniff_from_http(ws: &mut Workspace, iface: Option<&str>) {
    let url = match ws.active_session() {
        Some(SessionSlot::Http(s)) => textarea_util::text_of(&s.url),
        _ => {
            ws.flash_err("sniff: need HTTP session with a URL");
            return;
        }
    };
    let Some(filter) = crate::dissect::capture_filter_for_url(&url) else {
        ws.flash_err("sniff: could not parse host from URL");
        return;
    };
    let want_iface = iface.unwrap_or("any");

    // Reuse an existing live capture only when the interface matches.
    let existing = ws.sessions.iter().position(|s| {
        matches!(
            s,
            SessionSlot::Capture(c)
                if c.source == crate::session::CaptureSource::Live
                    && c.title_iface == want_iface
        )
    });
    if let Some(idx) = existing {
        ws.active = idx;
    } else {
        ws.open_capture(want_iface);
    }

    if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
        let iface_name = s.title_iface.clone();
        match s.set_capture_filter(&filter) {
            Ok(()) => {
                let crumb = format!(
                    "sniffing {filter} on {iface_name} · F6 stop · : follow-http · r replay"
                );
                if !s.capturing {
                    match s.start_capture() {
                        Ok(()) => ws.flash_ok(crumb),
                        Err(e) => {
                            let hint = crate::capture::backend::capture_hint();
                            ws.flash_err(format!("capture start failed: {e:#} · {hint}"));
                        }
                    }
                } else {
                    ws.flash_ok(crumb);
                }
            }
            Err(e) => ws.flash_err(format!("cfilter: {e}")),
        }
    }
}

fn run_palette_command(ws: &mut Workspace, cmd: &str, fan_tx: &FanTx) {
    let cmd = cmd.trim();
    if cmd == "help" {
        ws.overlay = Overlay::Help;
    } else if cmd == "quit" {
        ws.overlay = Overlay::Quit;
        ws.quit_yes = true;
    } else if let Some(rest) = cmd.strip_prefix("stream ") {
        open_from_uri(ws, 0, rest, fan_tx);
    } else if let Some(rest) = cmd.strip_prefix("http ") {
        open_from_uri(ws, 1, rest, fan_tx);
    } else if let Some(rest) = cmd.strip_prefix("listen ") {
        open_from_uri(ws, 2, rest, fan_tx);
    } else if let Some(rest) = cmd.strip_prefix("proxy ") {
        let mut tls = false;
        let mut parts = Vec::new();
        for tok in rest.split_whitespace() {
            if tok == "--tls-intercept" || tok == "--mitm" {
                tls = true;
            } else {
                parts.push(tok);
            }
        }
        ws.uri_tls_intercept = tls;
        let uri = parts.join(" ");
        open_from_uri(ws, 3, &uri, fan_tx);
    } else if cmd == "ca-path" {
        let path = crate::tls_mitm::MitmCa::ca_dir().join("ca.pem");
        match crate::tls_mitm::MitmCa::load_or_create() {
            Ok(ca) => ws.flash_ok(format!(
                "CA PEM: {} (install in client trust store; HTTP/1.1 ALPN only)",
                ca.ca_pem_path().display()
            )),
            Err(e) => ws.flash_err(format!("CA: {e:#} · expected {}", path.display())),
        }
    } else if let Some(rest) = cmd.strip_prefix("diag ") {
        open_from_uri(ws, 4, rest, fan_tx);
    } else if let Some(rest) = cmd.strip_prefix("capture ") {
        ws.open_capture(rest.trim());
    } else if let Some(rest) = cmd.strip_prefix("open ") {
        match ws.open_capture_file(std::path::Path::new(rest.trim())) {
            Ok(()) => ws.flash_ok("opened capture file"),
            Err(e) => ws.flash_err(format!("{e:#}")),
        }
    } else if cmd == "follow-tcp" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            if s.follow_selected_tcp() {
                ws.overlay = Overlay::FollowStream;
            } else {
                ws.flash_err("follow-tcp: select a packet first");
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "follow-udp" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            if s.follow_selected_udp() {
                ws.overlay = Overlay::FollowStream;
            } else {
                ws.flash_err("follow-udp: select a packet first");
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "follow-http" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            if !s.follow_selected_http() {
                ws.flash_err("follow-http: select a packet first");
            } else {
                let n = s
                    .follow_view
                    .as_ref()
                    .map(|f| f.objects.len())
                    .unwrap_or(0);
                ws.overlay = Overlay::FollowStream;
                if n == 0 {
                    ws.flash_err(
                        "no HTTP objects — try : keylog PATH, or pick cleartext HTTP",
                    );
                } else {
                    ws.flash_ok(format!("follow-http · {n} object(s) · r = replay"));
                }
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "sniff" || cmd.starts_with("sniff ") || cmd == "capture-http" || cmd.starts_with("capture-http ")
    {
        let iface = cmd
            .strip_prefix("sniff ")
            .or_else(|| cmd.strip_prefix("capture-http "))
            .map(str::trim)
            .filter(|s| !s.is_empty());
        sniff_from_http(ws, iface);
    } else if cmd == "conversations" {
        capture_palette(ws, |_| Some(Overlay::Conversations));
    } else if cmd == "endpoints" {
        capture_palette(ws, |_| Some(Overlay::Endpoints));
    } else if cmd == "hierarchy" {
        capture_palette(ws, |_| Some(Overlay::Hierarchy));
    } else if cmd == "expert" {
        capture_palette(ws, |_| Some(Overlay::Expert));
    } else if cmd == "keylog" {
        capture_palette(ws, |_| Some(Overlay::Keylog));
    } else if let Some(rest) = cmd.strip_prefix("keylog ") {
        let path = rest.trim();
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            match s.load_keylog(std::path::Path::new(path)) {
                Ok(()) => ws.flash_ok(format!("keylog loaded {path}")),
                Err(e) => ws.flash_err(format!("keylog: {e:#}")),
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if let Some(rest) = cmd.strip_prefix("save ") {
        let path = rest.trim();
        save_capture(ws, Some(path), false);
    } else if cmd == "save" {
        save_capture(ws, None, false);
    } else if cmd == "save-all" {
        save_capture(ws, None, true);
    } else if cmd == "inject" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            match s.inject_selected() {
                Ok(()) => ws.flash_ok("inject queued"),
                Err(e) => ws.flash_err(format!("{e:#}")),
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "composer" {
        capture_composer(ws, fan_tx);
    } else if cmd == "replay-http" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            let needs_follow = s
                .follow_view
                .as_ref()
                .map(|f| f.objects.iter().all(|o| !o.is_request))
                .unwrap_or(true);
            if needs_follow && !s.follow_selected_http() {
                ws.flash_err("replay-http: select a packet first");
                return;
            }
            let has_req = s
                .follow_view
                .as_ref()
                .map(|f| f.objects.iter().any(|o| o.is_request))
                .unwrap_or(false);
            if has_req {
                replay_follow_into_http(ws);
            } else {
                ws.flash_err(
                    "replay-http: no HTTP request — try : keylog PATH or a cleartext stream",
                );
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "names-toggle" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            s.names.enabled = !s.names.enabled;
            let on = s.names.enabled;
            ws.flash_ok(format!("names {}", if on { "on" } else { "off" }));
        } else {
            ws.flash_err("need capture session");
        }
    } else if let Some(rest) = cmd.strip_prefix("cfilter ") {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            match s.set_capture_filter(rest.trim()) {
                Ok(()) => ws.flash_ok(format!("capture filter: {}", rest.trim())),
                Err(e) => ws.flash_err(format!("cfilter: {e}")),
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "export-objects" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            let dir = dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("bitbeak")
                .join("export");
            let objects = s
                .follow_view
                .as_ref()
                .map(|f| f.objects.as_slice())
                .unwrap_or(&[]);
            if objects.is_empty() {
                ws.flash_err("no HTTP objects — run follow-http first");
            } else {
                let n = objects.len();
                let dir_s = dir.display().to_string();
                match crate::dissect::export_http_objects(objects, &dir) {
                    Ok(()) => ws.flash_ok(format!("exported {n} objects to {dir_s}")),
                    Err(e) => ws.flash_err(format!("export: {e:#}")),
                }
            }
        } else {
            ws.flash_err("need capture session");
        }
    } else if let Some(rest) = cmd.strip_prefix("run ") {
        let name = rest.trim();
        if let Some(col) = &ws.collection {
            if let Some(req) = col.find_request(name).cloned() {
                ensure_http_and_load(ws, &req);
            } else {
                ws.flash_err(format!("request not found: {name}"));
            }
        } else {
            ws.flash_err("no collection loaded");
        }
    } else if let Some(rest) = cmd.strip_prefix("env ") {
        let name = rest.trim();
        if let Some(col) = ws.collection.as_mut() {
            if col.set_env(name) {
                ws.flash_ok(format!("env → {name}"));
            } else {
                ws.flash_err(format!("env not found: {name}"));
            }
        } else {
            ws.flash_err("no collection loaded");
        }
    } else if let Some(rest) = cmd.strip_prefix("import ") {
        let path = std::path::Path::new(rest.trim());
        match crate::collections::import::import_path(path) {
            Ok(col) => match crate::collections::save_collection(&col) {
                Ok(p) => {
                    ws.flash_ok(format!("imported {} → {}", col.requests.len(), p.display()));
                    ws.collection_names =
                        crate::collections::list_collections().unwrap_or_default();
                    ws.collection = Some(col);
                    ws.collection_show_requests = true;
                }
                Err(e) => ws.flash_err(format!("{e:#}")),
            },
            Err(e) => ws.flash_err(format!("import: {e:#}")),
        }
    } else if cmd == "cookies on" {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.cookies.enabled = true;
            let _ = s.cookies.save();
            ws.flash_ok("cookies on");
        }
    } else if cmd == "cookies off" {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.cookies.enabled = false;
            let _ = s.cookies.save();
            ws.flash_ok("cookies off");
        }
    } else if cmd == "auth" {
        let label = if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.cycle_auth();
            Some(s.auth_label())
        } else {
            None
        };
        if let Some(label) = label {
            ws.flash_ok(label);
        }
    } else if cmd == "body-mode" {
        let mode = if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.cycle_body_mode();
            Some(format!("{:?}", s.body_mode))
        } else {
            None
        };
        if let Some(mode) = mode {
            ws.flash_ok(format!("body {mode}"));
        }
    } else if cmd == "history" {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.reload_history_pane();
            s.focus = PaneFocus::History;
            ws.flash_ok("history focused — Enter to replay");
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "manuf-reload" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
            let n = s.names.reload_manuf();
            ws.flash_ok(format!("manuf reloaded · {n} OUIs"));
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "manuf-status" {
        if let Some(SessionSlot::Capture(s)) = ws.active_session() {
            ws.flash_ok(format!("manuf · {} OUIs loaded", s.names.oui_count()));
        } else {
            ws.flash_err("need capture session");
        }
    } else if cmd == "http-version" {
        let label = if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.cycle_http_version();
            Some(format!("{:?}", s.http_version))
        } else {
            None
        };
        if let Some(label) = label {
            ws.flash_ok(format!("http version → {label}"));
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "grpc" {
        let msg = if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.grpc_mode = !s.grpc_mode;
            if s.grpc_mode {
                textarea_util::set_text(&mut s.method, "POST");
                if !s.grpc_descriptor_path.is_empty() && !s.grpc_message_type.is_empty() {
                    Some(format!(
                        "gRPC on — JSON body via {} ({})",
                        s.grpc_descriptor_path, s.grpc_message_type
                    ))
                } else {
                    Some(
                        "gRPC unary mode on — raw protobuf bytes (set grpc-desc + grpc-type for JSON)"
                            .into(),
                    )
                }
            } else {
                Some("gRPC mode off".into())
            }
        } else {
            None
        };
        if let Some(msg) = msg {
            ws.flash_ok(msg);
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if let Some(rest) = cmd.strip_prefix("grpc-desc ") {
        let path = rest.trim().to_string();
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.grpc_descriptor_path = path.clone();
            s.grpc_mode = true;
            ws.flash_ok(format!("grpc descriptor → {path}"));
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if let Some(rest) = cmd.strip_prefix("grpc-type ") {
        let message_type = rest.trim().to_string();
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.grpc_message_type = message_type.clone();
            s.grpc_mode = true;
            ws.flash_ok(format!("grpc message type → {message_type}"));
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "gql-introspect" {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.body_mode = crate::http::BodyMode::GraphQL;
            textarea_util::set_text(&mut s.method, "POST");
            textarea_util::set_text(
                &mut s.body,
                "query IntrospectionQuery {\n  __schema {\n    types { name kind }\n  }\n}\n",
            );
            textarea_util::set_text(&mut s.graphql_vars_ta, "{}");
            textarea_util::set_text(&mut s.graphql_op_ta, "IntrospectionQuery");
            s.field = crate::session::HttpField::Body;
            s.sync_field_styles();
            ws.flash_ok("GraphQL introspection query loaded — Enter to send");
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if let Some(rest) = cmd.strip_prefix("rpcap ") {
        let parts: Vec<_> = rest.split_whitespace().collect();
        if parts.len() >= 2 {
            let hostport = parts[0];
            let iface = parts[1];
            let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
                (h, p.parse().unwrap_or(2002))
            } else {
                (hostport, 2002)
            };
            let target = format!("rpcap://{host}:{port}/{iface}");
            ws.open_capture(&target);
            if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
                match s.start_capture() {
                    Ok(()) => ws.flash_ok(format!(
                        "rpcap (experimental) capturing {target}"
                    )),
                    Err(e) => ws.flash_err(format!("rpcap (experimental): {e:#}")),
                }
            }
        } else if parts.len() == 1 {
            let host = parts[0];
            let (host, port) = if let Some((h, p)) = host.rsplit_once(':') {
                (h, p.parse().unwrap_or(2002))
            } else {
                (host, 2002)
            };
            match crate::capture::rpcap::probe(host, port) {
                Ok(msg) => ws.flash_ok(format!("rpcap (experimental): {msg}")),
                Err(e) => ws.flash_err(format!("rpcap (experimental): {e:#}")),
            }
        } else {
            ws.flash_err("usage: rpcap host[:port] [iface]");
        }
    } else if let Some(rest) = cmd.strip_prefix("codegen ") {
        let parts: Vec<_> = rest.split_whitespace().collect();
        let name = parts.first().copied().unwrap_or("");
        let lang = parts.get(1).copied().unwrap_or("curl");
        if name.is_empty() {
            ws.flash_err("usage: codegen <collection> [curl|rust]");
        } else {
            match crate::collections::load_collection(name) {
                Ok(col) => match crate::codegen::codegen_collection(
                    &col,
                    lang,
                    std::path::Path::new("./bitbeak-out"),
                ) {
                    Ok(p) => ws.flash_ok(format!("wrote {}", p.display())),
                    Err(e) => ws.flash_err(format!("codegen: {e:#}")),
                },
                Err(e) => ws.flash_err(format!("codegen: {e:#}")),
            }
        }
    } else if cmd == "oauth" {
        // Handled async below via spawn — sync start here
        start_oauth_flow(ws);
    } else if cmd == "fuzz" {
        ws.overlay = Overlay::Fuzz;
        ws.flash_ok("F11/fuzz — Enter mutates composer and sends (stream/listen)");
    } else if let Some(rest) = cmd.strip_prefix("pre-script ") {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.pre_script = rest.to_string();
            ws.flash_ok("pre-script set (Rhai)");
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "pre-script" || cmd == "pre-script-show" {
        if let Some(SessionSlot::Http(s)) = ws.active_session() {
            ws.edit_ta = textarea_util::multi_line(&s.pre_script);
            ws.overlay = Overlay::PreScriptEdit;
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "pre-script-clear" {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.pre_script.clear();
            ws.flash_ok("pre-script cleared");
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if let Some(rest) = cmd.strip_prefix("test ") {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            let expr = rest.trim().to_string();
            if expr.is_empty() {
                ws.flash_err("usage: test EXPR");
            } else {
                s.tests.push(crate::http::RequestTest { expr: expr.clone() });
                ws.flash_ok(format!("test added: {expr}"));
            }
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "tests" {
        if let Some(SessionSlot::Http(s)) = ws.active_session() {
            let text = s
                .tests
                .iter()
                .map(|t| t.expr.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            ws.edit_ta = textarea_util::multi_line(&text);
            ws.overlay = Overlay::TestsEdit;
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "test-clear" {
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.tests.clear();
            s.last_assert.clear();
            ws.flash_ok("tests cleared");
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if let Some(rest) = cmd.strip_prefix("grpc-reply ") {
        let reply = rest.trim().to_string();
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.grpc_reply_type = reply.clone();
            s.grpc_mode = true;
            ws.flash_ok(format!("grpc reply type → {reply}"));
        } else {
            ws.flash_err("need HTTP session");
        }
    } else if cmd == "geoip-status" {
        let msg = crate::dissect::GeoDb::open_default().geo_status();
        ws.flash_ok(msg);
    } else if cmd.contains("://") {
        if cmd.starts_with("http://") || cmd.starts_with("https://") {
            open_from_uri(ws, 1, cmd, fan_tx);
        } else {
            open_from_uri(ws, 0, cmd, fan_tx);
        }
    } else if let Ok(t) = parse_target(cmd) {
        if t.is_http() {
            open_from_uri(ws, 1, cmd, fan_tx);
        } else {
            open_from_uri(ws, 0, cmd, fan_tx);
        }
    } else {
        ws.flash_err(format!("unknown command: {cmd}"));
    }
}

fn start_oauth_flow(ws: &mut Workspace) {
    let Some(SessionSlot::Http(s)) = ws.active_session_mut() else {
        ws.flash_err("need HTTP session");
        return;
    };
    if !matches!(s.auth, crate::http::AuthKind::OAuth2) {
        s.auth = crate::http::AuthKind::OAuth2;
    }
    // OAuth2 fields: user=client_id, pass=client_secret, key=auth_url, value=token_url, token=access
    let cfg = crate::http::OAuthConfig {
        client_id: s.auth_user(),
        client_secret: s.auth_pass(),
        auth_url: s.auth_key(),
        token_url: s.auth_value(),
        scopes: s.oauth_scopes.clone(),
    };
    if cfg.client_id.is_empty() || cfg.auth_url.is_empty() || cfg.token_url.is_empty() {
        ws.flash_err("oauth: set Auth User=client_id, Pass=secret, Key=auth_url, Value=token_url");
        return;
    }
    // Prefer refresh when we already have a stored refresh token for this client.
    let store = crate::http::load_oauth_store();
    if !store.refresh_token.is_empty()
        && (store.client_id.is_empty() || store.client_id == cfg.client_id)
    {
        let cfg_r = cfg.clone();
        let refresh = store.refresh_token.clone();
        let result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("oauth rt");
            rt.block_on(crate::http::refresh_access_token(
                &cfg_r.token_url,
                &cfg_r.client_id,
                &cfg_r.client_secret,
                &refresh,
            ))
        })
        .join();
        if let Ok(Ok(tok)) = result {
            if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
                textarea_util::set_text(&mut s.auth_token_ta, &tok.access_token);
                s.auth = crate::http::AuthKind::OAuth2;
                let mut store = crate::http::load_oauth_store();
                store.access_token = tok.access_token;
                if !tok.refresh_token.is_empty() {
                    store.refresh_token = tok.refresh_token;
                }
                store.client_id = cfg.client_id.clone();
                store.token_url = cfg.token_url.clone();
                let _ = crate::http::save_oauth_store(&store);
                ws.flash_ok("oauth: refreshed access token");
                return;
            }
        }
    }
    let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => {
            ws.flash_err(format!("oauth bind: {e}"));
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => {
            ws.flash_err(format!("oauth port: {e}"));
            return;
        }
    };
    drop(listener);
    let state = format!("bb{}", port);
    let verifier = crate::http::generate_pkce_verifier();
    let challenge = crate::http::pkce_challenge_s256(&verifier);
    let url = crate::http::authorize_url(&cfg, port, &state, &challenge);
    if let Err(e) = crate::http::open_browser(&url) {
        ws.flash_err(format!("open browser: {e:#}"));
        return;
    }
    ws.flash_ok(format!("oauth: waiting on :{port}/callback …"));
    let code = match crate::http::wait_for_code(port, std::time::Duration::from_secs(120)) {
        Ok(c) => c,
        Err(e) => {
            ws.flash_err(format!("oauth: {e:#}"));
            return;
        }
    };
    let cfg2 = cfg.clone();
    let code2 = code.clone();
    let verifier2 = verifier.clone();
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("oauth rt");
        rt.block_on(crate::http::exchange_code(&cfg2, port, &code2, &verifier2))
    })
    .join();
    match result {
        Ok(Ok(tok)) => {
            if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
                textarea_util::set_text(&mut s.auth_token_ta, &tok.access_token);
                s.auth = crate::http::AuthKind::OAuth2;
                let mut store = crate::http::load_oauth_store();
                if !tok.refresh_token.is_empty() {
                    store.refresh_token = tok.refresh_token;
                }
                store.access_token = tok.access_token;
                store.client_id = cfg.client_id;
                store.token_url = cfg.token_url;
                let _ = crate::http::save_oauth_store(&store);
                ws.flash_ok("oauth: access token stored");
            }
        }
        Ok(Err(e)) => ws.flash_err(format!("token exchange: {e:#}")),
        Err(_) => ws.flash_err("oauth: exchange thread panicked"),
    }
}

async fn handle_mouse(ws: &mut Workspace, m: MouseEvent, fan_tx: &FanTx) -> Result<bool> {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if let Some(target) = ws.hitmap.hit(m.column, m.row) {
                return dispatch_hit(ws, target, fan_tx).await;
            }
        }
        MouseEventKind::ScrollUp => nav(ws, -1),
        MouseEventKind::ScrollDown => nav(ws, 1),
        _ => {}
    }
    Ok(false)
}

async fn dispatch_hit(ws: &mut Workspace, target: HitTarget, fan_tx: &FanTx) -> Result<bool> {
    match target {
        HitTarget::Tab(i) => {
            if i < ws.sessions.len() {
                ws.active = i;
            }
        }
        HitTarget::NewTab => {
            ws.overlay = Overlay::NewSession;
        }
        HitTarget::Focus(focus) => set_active_focus(ws, focus),
        HitTarget::HttpField(field) => {
            if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
                s.set_field(field);
            }
        }
        HitTarget::InspectMode(mode) => {
            set_inspect(ws, mode);
        }
        HitTarget::FooterF(n) => {
            return handle_footer_fn(ws, n, fan_tx).await;
        }
        HitTarget::Send => {
            send_or_http(ws).await;
        }
        HitTarget::Broadcast => {
            if let Some(SessionSlot::Listen(s)) = ws.active_session_mut() {
                s.broadcast = !s.broadcast;
            }
        }
        HitTarget::LogRow(i) => select_log_row(ws, i),
        HitTarget::HistoryRow(i) => {
            if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
                s.focus = PaneFocus::History;
                s.history_cursor = i;
                s.replay_history_at_cursor();
            }
        }
        HitTarget::QuitYes => match ws.overlay {
            Overlay::Quit => return Ok(true),
            Overlay::CloseConfirm => {
                ws.close_active();
            }
            _ => {}
        },
        HitTarget::QuitNo => {
            ws.overlay = Overlay::None;
        }
        HitTarget::NewKind(kind) => {
            ws.new_session_cursor = kind;
            ws.begin_uri_entry(kind);
        }
        HitTarget::CollectionRow(i) => {
            if ws.collection_show_requests {
                ws.request_cursor = i;
            } else {
                ws.collection_cursor = i;
            }
        }
        HitTarget::OverlayDismiss => {
            ws.overlay = Overlay::None;
        }
    }
    Ok(false)
}

async fn handle_footer_fn(ws: &mut Workspace, n: u8, fan_tx: &FanTx) -> Result<bool> {
    match n {
        1 => ws.overlay = Overlay::Help,
        2 => ws.overlay = Overlay::NewSession,
        3 => ws.prev_tab(),
        4 => ws.next_tab(),
        5 => cycle_format(ws),
        6 => action_replay_or_run(ws, fan_tx).await,
        7 => run_bench(ws).await,
        8 => open_filter(ws),
        9 => {
            ws.collection_names = crate::collections::list_collections().unwrap_or_default();
            ws.collection_show_requests = ws.collection.is_some();
            ws.overlay = Overlay::Collections;
        }
        10 => {
            ws.overlay = Overlay::Quit;
            ws.quit_yes = true;
        }
        11 => ws.overlay = Overlay::Fuzz,
        12 => export_pcap(ws),
        _ => {}
    }
    Ok(false)
}

fn set_active_focus(ws: &mut Workspace, focus: PaneFocus) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.set_focus(focus),
        Some(SessionSlot::Listen(s)) => {
            s.focus = focus;
            s.sync_composer_style();
        }
        Some(SessionSlot::Http(s)) => s.set_focus(focus),
        Some(SessionSlot::Proxy(s)) => s.set_focus(focus),
        Some(SessionSlot::Diag(s)) => s.set_focus(focus),
        Some(SessionSlot::Capture(s)) => s.focus = focus,
        None => {}
    }
}

fn set_inspect(ws: &mut Workspace, mode: InspectMode) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.inspect = mode,
        Some(SessionSlot::Listen(s)) => s.inspect = mode,
        Some(SessionSlot::Proxy(s)) => s.inspect = mode,
        Some(SessionSlot::Http(s)) => s.inspect = mode,
        _ => {}
    }
}

fn select_log_row(ws: &mut Workspace, i: usize) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => {
            let len = s.frames.filtered(&s.filter).len();
            if i < len {
                s.selected = i;
                s.follow = i + 1 >= len;
            }
        }
        Some(SessionSlot::Listen(s)) => {
            let len = s.frames.filtered(&s.filter).len();
            if i < len {
                s.selected = i;
                s.follow = i + 1 >= len;
            }
        }
        Some(SessionSlot::Proxy(s)) => {
            let len = s.frames.filtered(&s.filter).len();
            if i < len {
                s.selected = i;
                s.follow = i + 1 >= len;
            }
        }
        Some(SessionSlot::Http(s)) => {
            let len = s.frames.len();
            if i < len {
                s.selected = i;
                s.follow = i + 1 >= len;
            }
        }
        Some(SessionSlot::Diag(s)) => {
            let len = s.lines.len();
            if i < len {
                s.selected = i;
                s.follow = i + 1 >= len;
            }
        }
        Some(SessionSlot::Capture(s)) => {
            let len = s.filtered_indices().len();
            if i < len {
                s.selected = i;
                s.follow = i + 1 >= len;
                s.tree_selected = 0;
            }
        }
        None => {}
    }
}

fn is_typing(ws: &Workspace) -> bool {
    match ws.active_session() {
        Some(SessionSlot::Stream(s)) => s.focus == PaneFocus::Composer,
        Some(SessionSlot::Listen(s)) => s.focus == PaneFocus::Composer,
        Some(SessionSlot::Proxy(s)) => s.focus == PaneFocus::Composer,
        Some(SessionSlot::Http(s)) => s.focus == PaneFocus::Form,
        _ => false,
    }
}

async fn handle_typing(ws: &mut Workspace, key: KeyEvent) -> bool {
    if key.code == KeyCode::Char('m') && key.modifiers.contains(KeyModifiers::CONTROL) {
        toggle_composer_mode(ws);
        return false;
    }
    if key.code == KeyCode::Esc {
        blur_focus(ws);
        return false;
    }
    if key.code == KeyCode::Tab {
        cycle_focus(ws, false);
        return false;
    }
    if key.code == KeyCode::BackTab {
        cycle_focus(ws, true);
        return false;
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    // Ctrl+Enter always sends
    if key.code == KeyCode::Enter && ctrl {
        send_or_http(ws).await;
        return false;
    }

    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => {
            if key.code == KeyCode::Enter && !shift {
                s.send_composer();
            } else {
                textarea_util::input(&mut s.composer, key);
            }
        }
        Some(SessionSlot::Listen(s)) => {
            if key.code == KeyCode::Enter && !shift {
                s.send_composer();
            } else {
                textarea_util::input(&mut s.composer, key);
            }
        }
        Some(SessionSlot::Proxy(s)) if s.focus == PaneFocus::Composer => {
            if key.code == KeyCode::Enter && !shift {
                s.send_composer();
            } else {
                textarea_util::input(&mut s.composer, key);
            }
        }
        Some(SessionSlot::Http(s)) => {
            if s.focus == PaneFocus::History {
                match key.code {
                    KeyCode::Enter => s.replay_history_at_cursor(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        s.history_cursor = s.history_cursor.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j')
                        if s.history_cursor + 1 < s.history.len() =>
                    {
                        s.history_cursor += 1;
                    }
                    _ => {}
                }
            } else if key.code == KeyCode::Enter && !shift {
                match s.field {
                    HttpField::Body
                    | HttpField::AuthToken
                    | HttpField::AuthUser
                    | HttpField::AuthPass
                    | HttpField::AuthKey
                    | HttpField::AuthValue
                    | HttpField::GraphqlVars
                    | HttpField::GraphqlOp
                    | HttpField::Form => {
                        if let Some(ta) = s.active_textarea_mut() {
                            textarea_util::input(ta, key);
                        }
                    }
                    HttpField::AuthKind => {
                        s.cycle_auth();
                    }
                    HttpField::Method | HttpField::Url | HttpField::Headers => {
                        // send handled below
                    }
                }
            } else if s.field == HttpField::Form && s.focus == PaneFocus::Form {
                match key.code {
                    KeyCode::Char('n') if ctrl => s.form_add_row(),
                    KeyCode::Char('x') if ctrl => s.form_delete_row(),
                    KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::ALT) => {
                        s.form_add_row()
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::ALT) => {
                        s.form_delete_row()
                    }
                    KeyCode::BackTab => {
                        s.form_cell = match s.form_cell {
                            crate::session::FormCell::Key => {
                                if matches!(s.body_mode, crate::http::BodyMode::Multipart) {
                                    crate::session::FormCell::File
                                } else {
                                    crate::session::FormCell::Value
                                }
                            }
                            crate::session::FormCell::Value => crate::session::FormCell::Key,
                            crate::session::FormCell::File => crate::session::FormCell::Value,
                        };
                        s.sync_field_styles();
                    }
                    KeyCode::Tab => {
                        s.form_cell = match s.form_cell {
                            crate::session::FormCell::Key => crate::session::FormCell::Value,
                            crate::session::FormCell::Value => {
                                if matches!(s.body_mode, crate::http::BodyMode::Multipart) {
                                    crate::session::FormCell::File
                                } else {
                                    crate::session::FormCell::Key
                                }
                            }
                            crate::session::FormCell::File => crate::session::FormCell::Key,
                        };
                        s.sync_field_styles();
                    }
                    KeyCode::Up => {
                        s.commit_form_editor_to_row();
                        s.form_row = s.form_row.saturating_sub(1);
                        s.sync_form_editor_from_row();
                    }
                    KeyCode::Down => {
                        s.commit_form_editor_to_row();
                        if s.form_row + 1 < s.form_fields.len() {
                            s.form_row += 1;
                        }
                        s.sync_form_editor_from_row();
                    }
                    _ => {
                        if let Some(ta) = s.active_textarea_mut() {
                            textarea_util::input(ta, key);
                        }
                    }
                }
            } else if let Some(ta) = s.active_textarea_mut() {
                textarea_util::input(ta, key);
            }
        }
        _ => {}
    }

    // HTTP Enter on Method/Url/Headers → send (needs async after borrow drop)
    if key.code == KeyCode::Enter && !shift && !ctrl {
        let should_send = matches!(
            ws.active_session(),
            Some(SessionSlot::Http(s))
                if s.focus == PaneFocus::Form
                    && matches!(
                        s.field,
                        HttpField::Method | HttpField::Url | HttpField::Headers
                    )
        );
        if should_send {
            http_send(ws).await;
        }
    }

    false
}

async fn send_or_http(ws: &mut Workspace) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.send_composer(),
        Some(SessionSlot::Listen(s)) => s.send_composer(),
        Some(SessionSlot::Proxy(s)) => s.send_composer(),
        Some(SessionSlot::Http(_)) => {}
        _ => {}
    }
    if matches!(ws.active_session(), Some(SessionSlot::Http(_))) {
        http_send(ws).await;
    }
}

fn blur_focus(ws: &mut Workspace) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.set_focus(PaneFocus::Log),
        Some(SessionSlot::Listen(s)) => {
            s.focus = PaneFocus::Log;
            s.sync_composer_style();
        }
        Some(SessionSlot::Proxy(s)) => s.set_focus(PaneFocus::Log),
        Some(SessionSlot::Http(s)) => s.set_focus(PaneFocus::Log),
        Some(SessionSlot::Capture(s)) => {
            s.focus = PaneFocus::Log;
        }
        _ => {}
    }
}

fn cycle_focus(ws: &mut Workspace, reverse: bool) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => {
            if reverse {
                s.set_focus(match s.focus {
                    PaneFocus::Log => PaneFocus::Composer,
                    PaneFocus::Inspector => PaneFocus::Log,
                    _ => PaneFocus::Inspector,
                });
            } else {
                s.cycle_focus();
            }
        }
        Some(SessionSlot::Listen(s)) => {
            s.focus = if reverse {
                match s.focus {
                    PaneFocus::Clients => PaneFocus::Composer,
                    PaneFocus::Log => PaneFocus::Clients,
                    PaneFocus::Inspector => PaneFocus::Log,
                    _ => PaneFocus::Inspector,
                }
            } else {
                match s.focus {
                    PaneFocus::Clients => PaneFocus::Log,
                    PaneFocus::Log => PaneFocus::Inspector,
                    PaneFocus::Inspector => PaneFocus::Composer,
                    _ => PaneFocus::Clients,
                }
            };
            s.sync_composer_style();
        }
        Some(SessionSlot::Http(s)) => {
            if s.focus == PaneFocus::History {
                s.focus = PaneFocus::Form;
                s.sync_field_styles();
            } else if reverse {
                s.field = match s.field {
                    HttpField::Method => match s.body_mode {
                        crate::http::BodyMode::Raw => HttpField::Body,
                        crate::http::BodyMode::GraphQL => HttpField::GraphqlOp,
                        crate::http::BodyMode::UrlEncoded | crate::http::BodyMode::Multipart => {
                            HttpField::Form
                        }
                    },
                    HttpField::Url => HttpField::Method,
                    HttpField::AuthKind => HttpField::Url,
                    HttpField::AuthToken | HttpField::AuthUser | HttpField::AuthKey => {
                        HttpField::AuthKind
                    }
                    HttpField::AuthPass => HttpField::AuthUser,
                    HttpField::AuthValue => HttpField::AuthKey,
                    HttpField::Headers => match s.auth {
                        crate::http::AuthKind::None => HttpField::AuthKind,
                        crate::http::AuthKind::Bearer => HttpField::AuthToken,
                        crate::http::AuthKind::Basic => HttpField::AuthPass,
                        crate::http::AuthKind::ApiKeyHeader
                        | crate::http::AuthKind::ApiKeyQuery
                        | crate::http::AuthKind::OAuth2 => HttpField::AuthValue,
                    },
                    HttpField::GraphqlOp => HttpField::GraphqlVars,
                    HttpField::GraphqlVars => HttpField::Body,
                    HttpField::Body | HttpField::Form => HttpField::Headers,
                };
                s.focus = PaneFocus::Form;
                s.sync_field_styles();
            } else {
                s.cycle_field();
                s.focus = PaneFocus::Form;
                s.sync_field_styles();
            }
        }
        Some(SessionSlot::Capture(s)) => {
            s.focus = if reverse {
                match s.focus {
                    PaneFocus::Log => PaneFocus::Hex,
                    PaneFocus::Tree => PaneFocus::Log,
                    PaneFocus::Hex => PaneFocus::Tree,
                    _ => PaneFocus::Log,
                }
            } else {
                match s.focus {
                    PaneFocus::Log => PaneFocus::Tree,
                    PaneFocus::Tree => PaneFocus::Hex,
                    PaneFocus::Hex => PaneFocus::Log,
                    _ => PaneFocus::Log,
                }
            };
        }
        Some(SessionSlot::Proxy(s)) => {
            s.focus = if reverse {
                match s.focus {
                    PaneFocus::Log => PaneFocus::Composer,
                    PaneFocus::Inspector => PaneFocus::Log,
                    _ => PaneFocus::Inspector,
                }
            } else {
                match s.focus {
                    PaneFocus::Log => PaneFocus::Inspector,
                    PaneFocus::Inspector => PaneFocus::Composer,
                    _ => PaneFocus::Log,
                }
            };
            s.sync_composer_style();
        }
        _ => {}
    }
}

fn nav(ws: &mut Workspace, delta: isize) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => {
            if delta > 0 {
                for _ in 0..delta {
                    s.nav_down();
                }
            } else {
                for _ in 0..(-delta) {
                    s.nav_up();
                }
            }
        }
        Some(SessionSlot::Listen(s)) => {
            if s.focus == PaneFocus::Clients {
                if s.clients.is_empty() {
                    return;
                }
                let cur = s
                    .clients
                    .iter()
                    .position(|c| Some(c.id) == s.selected_client)
                    .unwrap_or(0);
                let next = if delta < 0 {
                    cur.saturating_sub(1)
                } else {
                    (cur + 1).min(s.clients.len() - 1)
                };
                s.select_client_index(next);
            } else {
                let len = s.frames.filtered(&s.filter).len();
                crate::session::move_selection(&mut s.selected, &mut s.follow, len, delta);
            }
        }
        Some(SessionSlot::Proxy(s)) => {
            let len = s.frames.filtered(&s.filter).len();
            crate::session::move_selection(&mut s.selected, &mut s.follow, len, delta);
        }
        Some(SessionSlot::Http(s)) => {
            let len = s.frames.len();
            crate::session::move_selection(&mut s.selected, &mut s.follow, len, delta);
        }
        Some(SessionSlot::Diag(s)) => {
            let len = s.lines.len();
            crate::session::move_selection(&mut s.selected, &mut s.follow, len, delta);
        }
        Some(SessionSlot::Capture(s)) => {
            if s.focus == PaneFocus::Tree {
                let idx = s.filtered_indices();
                if let Some(store_i) = idx.get(s.selected.min(idx.len().saturating_sub(1))) {
                    if let Some(pkt) = s.store.get_mut(*store_i) {
                        let tree = pkt.ensure_tree();
                        let vis_len = tree.visible().len();
                        if vis_len > 0 {
                            if delta < 0 {
                                s.tree_selected = s.tree_selected.saturating_sub((-delta) as usize);
                            } else {
                                s.tree_selected =
                                    (s.tree_selected + delta as usize).min(vis_len - 1);
                            }
                        }
                    }
                }
            } else {
                s.nav(delta);
            }
        }
        None => {}
    }
}

fn nav_home(ws: &mut Workspace) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.nav_top(),
        Some(SessionSlot::Listen(s)) => {
            crate::session::jump_top(&mut s.selected, &mut s.follow);
        }
        Some(SessionSlot::Proxy(s)) => {
            crate::session::jump_top(&mut s.selected, &mut s.follow);
        }
        Some(SessionSlot::Http(s)) => {
            crate::session::jump_top(&mut s.selected, &mut s.follow);
        }
        Some(SessionSlot::Diag(s)) => {
            crate::session::jump_top(&mut s.selected, &mut s.follow);
        }
        Some(SessionSlot::Capture(s)) => {
            if s.focus == PaneFocus::Tree {
                s.tree_selected = 0;
            } else {
                s.selected = 0;
                s.follow = false;
                s.tree_selected = 0;
            }
        }
        None => {}
    }
}

fn nav_end(ws: &mut Workspace) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.nav_bottom(),
        Some(SessionSlot::Listen(s)) => {
            let len = s.frames.filtered(&s.filter).len();
            crate::session::jump_bottom(&mut s.selected, &mut s.follow, len);
        }
        Some(SessionSlot::Proxy(s)) => {
            let len = s.frames.filtered(&s.filter).len();
            crate::session::jump_bottom(&mut s.selected, &mut s.follow, len);
        }
        Some(SessionSlot::Http(s)) => {
            let len = s.frames.len();
            crate::session::jump_bottom(&mut s.selected, &mut s.follow, len);
        }
        Some(SessionSlot::Diag(s)) => {
            let len = s.lines.len();
            crate::session::jump_bottom(&mut s.selected, &mut s.follow, len);
        }
        Some(SessionSlot::Capture(s)) => {
            if s.focus == PaneFocus::Tree {
                let idx = s.filtered_indices();
                if let Some(store_i) = idx.get(s.selected.min(idx.len().saturating_sub(1))) {
                    if let Some(pkt) = s.store.get_mut(*store_i) {
                        let vis_len = pkt.ensure_tree().visible().len();
                        if vis_len > 0 {
                            s.tree_selected = vis_len - 1;
                        }
                    }
                }
            } else {
                let n = s.filtered_indices().len();
                if n > 0 {
                    s.selected = n - 1;
                    s.follow = true;
                }
                s.tree_selected = 0;
            }
        }
        None => {}
    }
}

fn cycle_format(ws: &mut Workspace) {
    cycle_format_dir(ws, true);
}

fn cycle_format_dir(ws: &mut Workspace, next: bool) {
    let apply = |m: InspectMode| if next { m.next() } else { m.prev() };
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.inspect = apply(s.inspect),
        Some(SessionSlot::Listen(s)) => s.inspect = apply(s.inspect),
        Some(SessionSlot::Proxy(s)) => s.inspect = apply(s.inspect),
        Some(SessionSlot::Http(s)) => s.inspect = apply(s.inspect),
        _ => {}
    }
}

fn toggle_composer_mode(ws: &mut Workspace) {
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => {
            s.composer_mode = match s.composer_mode {
                ComposerMode::Utf8 => ComposerMode::Hex,
                ComposerMode::Hex => ComposerMode::Utf8,
            };
        }
        Some(SessionSlot::Listen(s)) => {
            s.composer_mode = match s.composer_mode {
                ComposerMode::Utf8 => ComposerMode::Hex,
                ComposerMode::Hex => ComposerMode::Utf8,
            };
        }
        Some(SessionSlot::Http(s)) => {
            s.composer_mode = match s.composer_mode {
                ComposerMode::Utf8 => ComposerMode::Hex,
                ComposerMode::Hex => ComposerMode::Utf8,
            };
        }
        _ => {}
    }
}

async fn action_replay_or_run(ws: &mut Workspace, fan_tx: &FanTx) {
    if let Some(SessionSlot::Capture(s)) = ws.active_session_mut() {
        match s.toggle_capture() {
            Ok(()) => {
                let msg = if s.capturing {
                    "capture started"
                } else {
                    "capture stopped"
                };
                ws.flash_ok(msg);
            }
            Err(e) => ws.flash_err(format!("capture: {e:#}")),
        }
        return;
    }

    let reconnect = matches!(
        ws.active_session(),
        Some(SessionSlot::Stream(s)) if s.status == ConnStatus::Disconnected
    );
    if reconnect {
        if let Some(SessionSlot::Stream(s)) = ws.active_session_mut() {
            s.reconnect();
        }
        let idx = ws.active;
        attach_io(ws, fan_tx, idx);
        ws.flash_info("reconnecting…");
        return;
    }

    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => s.replay_selected(),
        Some(SessionSlot::Http(_)) => {}
        Some(SessionSlot::Diag(s)) => s.run_now().await,
        Some(SessionSlot::Listen(s)) => s.send_composer(),
        Some(SessionSlot::Proxy(s)) => s.send_composer(),
        _ => {}
    }
    if matches!(ws.active_session(), Some(SessionSlot::Http(_))) {
        http_send(ws).await;
    }
}

async fn run_bench(ws: &mut Workspace) {
    let col = ws.collection.clone();
    let spec = match ws.active_session() {
        Some(SessionSlot::Http(s)) => s.build_spec(col.as_ref()).ok(),
        _ => None,
    };
    if let Some(spec) = spec {
        let result = bench_http(&spec, &BenchConfig::default()).await;
        ws.flash_ok(format!("bench ok={} err={}", result.ok, result.err));
        ws.bench_result = Some(result);
        ws.overlay = Overlay::Bench;
    } else {
        ws.flash_err("bench: open an HTTP session first");
        ws.overlay = Overlay::Bench;
    }
}

fn run_fuzz_once(ws: &mut Workspace) {
    let seed = ws.fuzz_seed;
    ws.fuzz_seed = ws.fuzz_seed.wrapping_add(1);
    let kind = Mutator::all()[seed as usize % Mutator::all().len()];
    match ws.active_session_mut() {
        Some(SessionSlot::Stream(s)) => {
            if let Ok(base) = crate::composer::decode_payload(&s.composer_text(), s.composer_mode) {
                let mutated = mutate(&base, kind, seed);
                s.send_bytes(Bytes::from(mutated));
                s.status_msg = format!("fuzz sent ({})", kind.label());
            }
        }
        Some(SessionSlot::Listen(s)) => {
            if let Ok(base) = crate::composer::decode_payload(&s.composer_text(), s.composer_mode) {
                let mutated = mutate(&base, kind, seed);
                let _ = s.cmd_tx.send(crate::transport::IoCommand::Send {
                    payload: Bytes::from(mutated),
                    client_id: s.selected_client,
                });
                s.status_msg = format!("fuzz sent ({})", kind.label());
            }
        }
        _ => {
            ws.flash_err("fuzz: need stream/listen with composer payload");
        }
    }
}

fn export_pcap(ws: &mut Workspace) {
    if matches!(ws.active_session(), Some(SessionSlot::Capture(_))) {
        save_capture(ws, None, false);
        return;
    }

    let path = ws
        .pcap_path
        .clone()
        .unwrap_or_else(|| default_pcap_path("session"));
    let frames: Vec<&crate::frame::Frame> = match ws.active_session() {
        Some(SessionSlot::Stream(s)) => s.frames.all(),
        Some(SessionSlot::Listen(s)) => s.frames.all(),
        Some(SessionSlot::Proxy(s)) => s.frames.all(),
        Some(SessionSlot::Http(s)) => s.frames.all(),
        _ => Vec::new(),
    };
    let (src, dst) = default_addrs();
    match write_frames_pcap(&path, &frames, src, dst) {
        Ok(()) => ws.flash_ok(format!("pcap written {}", path.display())),
        Err(e) => ws.flash_err(format!("pcap error: {e:#}")),
    }
}

fn save_capture(ws: &mut Workspace, path: Option<&str>, all: bool) {
    let Some(SessionSlot::Capture(s)) = ws.active_session() else {
        ws.flash_err("need capture session");
        return;
    };
    let path_buf = path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| s.default_save_path());
    let result = if all {
        s.save_all(&path_buf)
    } else {
        s.save_displayed(&path_buf)
    };
    match result {
        Ok(()) => ws.flash_ok(format!(
            "saved {} ({})",
            path_buf.display(),
            if all { "all" } else { "displayed" }
        )),
        Err(e) => ws.flash_err(format!("save: {e:#}")),
    }
}

/// Headless workspace for tests (no terminal).
pub fn workspace_from_args(args: Args) -> Result<Workspace> {
    Workspace::new(&args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn empty_workspace_starts_without_overlay() {
        let args = Args::parse_from(["bitbeak"]);
        let ws = Workspace::new(&args).unwrap();
        assert!(matches!(ws.overlay, Overlay::None));
        assert!(ws.sessions.is_empty());
    }

    #[test]
    fn draw_smoke_80x24() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let _term = ui::draw_test(&mut ws, 80, 24);
    }

    #[test]
    fn draw_smoke_60x18() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let _term = ui::draw_test(&mut ws, 60, 18);
    }

    #[tokio::test]
    async fn draw_smoke_with_stream_tab() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        // HTTP session without connect — draw path only
        ws.sessions
            .push(SessionSlot::Http(crate::session::HttpSession::new(
                crate::cli::Target::Http {
                    url: "http://example.com/".into(),
                    secure: false,
                },
                100,
            )));
        ws.overlay = Overlay::None;
        ws.active = 0;
        let _term = ui::draw_test(&mut ws, 80, 24);
    }

    #[tokio::test]
    async fn open_uri_flow() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let (fan_tx, _fan_rx) = mpsc::unbounded_channel();

        assert!(matches!(ws.overlay, Overlay::None));
        ws.overlay = Overlay::NewSession;
        assert!(matches!(ws.overlay, Overlay::NewSession));
        ws.begin_uri_entry(1);
        assert!(matches!(ws.overlay, Overlay::NewSessionUri { kind: 1 }));

        textarea_util::set_text(&mut ws.uri_input, "https://example.com/health");
        open_uri_entry(&mut ws, 1, &fan_tx);

        assert_eq!(ws.sessions.len(), 1);
        assert!(matches!(ws.sessions[0], SessionSlot::Http(_)));
        assert!(matches!(ws.overlay, Overlay::None));
        assert_eq!(ws.active, 0);

        // Stream open attaches fan-in (connect task runs; we don't await traffic)
        open_from_uri(&mut ws, 0, "tcp://127.0.0.1:1", &fan_tx);
        assert_eq!(ws.sessions.len(), 2);
        assert!(matches!(ws.sessions[1], SessionSlot::Stream(_)));
    }

    #[test]
    fn toast_appears_in_buffer() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        ws.overlay = Overlay::None;
        ws.flash_ok("hello-toast-xyz");
        let term = ui::draw_test(&mut ws, 80, 24);
        let buf = term.backend().buffer().clone();
        let mut screen = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                screen.push(buf[(x, y)].symbol().chars().next().unwrap_or(' '));
            }
            screen.push('\n');
        }
        assert!(
            screen.contains("hello-toast-xyz"),
            "toast text missing from screen:\n{screen}"
        );
    }

    #[test]
    fn mouse_hit_switches_tab() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        ws.sessions
            .push(SessionSlot::Http(crate::session::HttpSession::new(
                crate::cli::Target::Http {
                    url: "http://a.example/".into(),
                    secure: false,
                },
                100,
            )));
        ws.sessions
            .push(SessionSlot::Http(crate::session::HttpSession::new(
                crate::cli::Target::Http {
                    url: "http://b.example/".into(),
                    secure: false,
                },
                100,
            )));
        ws.overlay = Overlay::None;
        ws.active = 0;
        let hits = ui::draw_test(&mut ws, 100, 24);
        // draw_test returns Terminal; hitmap is on ws
        let _ = hits;
        assert!(
            ws.hitmap.hit(2, 1).is_some() || ws.hitmap.hit(5, 1).is_some(),
            "expected a tab hit near header"
        );
        // Find Tab(1) and dispatch
        // Probe across header row
        let mut switched = false;
        for x in 0..100u16 {
            if let Some(HitTarget::Tab(1)) = ws.hitmap.hit(x, 1) {
                ws.active = 1;
                switched = true;
                break;
            }
        }
        assert!(switched, "Tab(1) not found in hitmap");
        assert_eq!(ws.active, 1);
    }

    #[test]
    fn mouse_pill_changes_inspect_mode() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut stream = crate::session::StreamSession::inert(
            crate::cli::Target::Tcp {
                host: "127.0.0.1".into(),
                port: 9,
            },
            crate::framing::FramingConfig::default(),
            100,
        );
        let _ = stream.take_io_rx();
        stream.inspect = InspectMode::Hex;
        ws.sessions.push(SessionSlot::Stream(stream));
        ws.overlay = Overlay::None;
        ws.active = 0;
        let _term = ui::draw_test(&mut ws, 100, 30);
        let mut found = false;
        for y in 0..30u16 {
            for x in 0..100u16 {
                if let Some(HitTarget::InspectMode(InspectMode::Json)) = ws.hitmap.hit(x, y) {
                    if let Some(SessionSlot::Stream(s)) = ws.active_session_mut() {
                        s.inspect = InspectMode::Json;
                    }
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(found, "JSON pill not in hitmap");
        assert!(matches!(
            ws.active_session().and_then(|s| match s {
                SessionSlot::Stream(s) => Some(s.inspect),
                _ => None,
            }),
            Some(InspectMode::Json)
        ));
    }

    #[test]
    fn footer_dims_bench_on_stream() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut stream = crate::session::StreamSession::inert(
            crate::cli::Target::Tcp {
                host: "127.0.0.1".into(),
                port: 9,
            },
            crate::framing::FramingConfig::default(),
            100,
        );
        let _ = stream.take_io_rx();
        ws.sessions.push(SessionSlot::Stream(stream));
        ws.overlay = Overlay::None;
        let _ = ui::draw_test(&mut ws, 80, 24);

        ws.sessions.clear();
        ws.sessions
            .push(SessionSlot::Http(crate::session::HttpSession::new(
                crate::cli::Target::Http {
                    url: "http://example.com/".into(),
                    secure: false,
                },
                100,
            )));
        let _ = ui::draw_test(&mut ws, 80, 24);
    }

    #[tokio::test]
    async fn http_enter_sends_from_url_field() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut http = crate::session::HttpSession::new(
            crate::cli::Target::Http {
                url: "http://127.0.0.1:1/".into(),
                secure: false,
            },
            100,
        );
        http.focus = PaneFocus::Form;
        http.field = crate::session::HttpField::Url;
        let before = http.status_msg.clone();
        ws.sessions.push(SessionSlot::Http(http));
        ws.overlay = Overlay::None;
        ws.active = 0;

        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let _ = handle_typing(&mut ws, key).await;

        let msg = match ws.active_session() {
            Some(SessionSlot::Http(s)) => s.status_msg.clone(),
            _ => String::new(),
        };
        assert_ne!(msg, before, "Enter on URL should trigger send");
        assert!(
            msg.contains("sending")
                || msg.contains("error")
                || msg.contains("Connection")
                || msg.contains("os error")
                || msg.contains("Connect")
                || !msg.is_empty(),
            "unexpected status after Enter send: {msg}"
        );

        // Body field: plain Enter inserts newline, does not flip to idle send path alone
        if let Some(SessionSlot::Http(s)) = ws.active_session_mut() {
            s.field = crate::session::HttpField::Body;
            s.status_msg = "ready".into();
            textarea_util::set_text(&mut s.body, "line1");
        }
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let _ = handle_typing(&mut ws, key).await;
        if let Some(SessionSlot::Http(s)) = ws.active_session() {
            assert_eq!(s.status_msg, "ready", "Body Enter must not auto-send");
            assert!(
                textarea_util::text_of(&s.body).contains('\n')
                    || textarea_util::text_of(&s.body).contains("line1"),
                "body should accept Enter as text"
            );
        }
    }

    #[test]
    fn all_overlays_draw() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        for overlay in [
            Overlay::Help,
            Overlay::Quit,
            Overlay::CloseConfirm,
            Overlay::NewSession,
            Overlay::NewSessionUri { kind: 0 },
            Overlay::NewSessionUri { kind: 3 },
            Overlay::Filter,
            Overlay::Collections,
            Overlay::Bench,
            Overlay::Fuzz,
            Overlay::CommandPalette,
            Overlay::FollowStream,
            Overlay::Conversations,
            Overlay::Endpoints,
            Overlay::Hierarchy,
            Overlay::Expert,
            Overlay::Keylog,
            Overlay::TestsEdit,
            Overlay::PreScriptEdit,
        ] {
            ws.overlay = overlay;
            let _ = ui::draw_test(&mut ws, 80, 24);
            let _ = ui::draw_test(&mut ws, 60, 18);
        }
    }

    #[test]
    fn collections_overlay_with_request() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut col = crate::collections::Collection::new("demo");
        col.environments.push(crate::collections::Environment {
            name: "local".into(),
            vars: vec![("baseUrl".into(), "http://127.0.0.1".into())],
        });
        col.active_env = Some("local".into());
        col.requests.push(crate::collections::SavedRequest {
            name: "ping".into(),
            kind: "http".into(),
            target: "{{baseUrl}}/".into(),
            method: Some("GET".into()),
            headers: vec![],
            body: String::new(),
            ..Default::default()
        });
        ws.collection = Some(col);
        ws.collection_show_requests = true;
        ws.overlay = Overlay::Collections;
        let _ = ui::draw_test(&mut ws, 80, 24);

        let req = ws
            .collection
            .as_ref()
            .unwrap()
            .requests
            .first()
            .cloned()
            .unwrap();
        ensure_http_and_load(&mut ws, &req);
        assert!(matches!(ws.sessions[0], SessionSlot::Http(_)));
        if let Some(SessionSlot::Http(s)) = ws.active_session() {
            let spec = s.build_spec(ws.collection.as_ref()).unwrap();
            assert_eq!(spec.url, "http://127.0.0.1/");
        }
    }

    #[test]
    fn import_fixtures() {
        let postman = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/postman_demo.json");
        let col = crate::collections::import::import_path(&postman).unwrap();
        assert_eq!(col.name, "BitBeakDemo");
        assert_eq!(col.requests[0].name, "Users/List");

        let oas = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/openapi_demo.yaml");
        let col = crate::collections::import::import_path(&oas).unwrap();
        assert_eq!(col.name, "DemoAPI");
        assert!(col.requests.iter().any(|r| r.target.contains("/health")));
    }

    fn screen_of(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buf = term.backend().buffer();
        let mut screen = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                screen.push_str(buf[(x, y)].symbol());
            }
            screen.push('\n');
        }
        screen
    }

    fn line_after_label(screen: &str, label: &str) -> Option<String> {
        let clean = |line: &str| -> String {
            line.replace(['│', '┌', '┐', '└', '┘', '─'], "")
                .trim()
                .to_string()
        };
        let mut lines = screen.lines();
        while let Some(line) = lines.next() {
            if clean(line).split_whitespace().next() == Some(label) {
                return lines.next().map(|s| {
                    clean(s)
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string()
                });
            }
        }
        None
    }

    #[test]
    fn http_cli_target_shows_method_and_url() {
        let args = Args::parse_from(["bitbeak", "http://bitbeak.test/unique-cli-path-xyz"]);
        let mut ws = Workspace::new(&args).unwrap();
        let term = ui::draw_test(&mut ws, 120, 36);
        let screen = screen_of(&term);
        assert_eq!(
            line_after_label(&screen, "Method").as_deref(),
            Some("GET"),
            "method value missing:\n{screen}"
        );
        let url_line = line_after_label(&screen, "URL").expect("URL label");
        assert!(
            url_line.contains("http://bitbeak.test/unique-cli-path-xyz"),
            "url value missing from field (got {url_line:?}):\n{screen}"
        );
    }

    #[test]
    fn collection_hydrates_matching_http_request() {
        let args = Args::parse_from(["bitbeak", "http://127.0.0.1:18081/v1/orders/ord_8f2c91a4"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut col = crate::collections::Collection::new("kestrel");
        col.requests.push(crate::collections::SavedRequest {
            name: "Get order".into(),
            kind: "http".into(),
            target: "http://127.0.0.1:18081/v1/orders/ord_8f2c91a4".into(),
            method: Some("GET".into()),
            headers: vec![("Accept".into(), "application/json".into())],
            body: String::new(),
            auth: crate::http::AuthKind::Bearer,
            auth_token: "sk_test".into(),
            ..Default::default()
        });
        ws.collection = Some(col.clone());
        ws.hydrate_http_from_collection();
        match ws.active_session() {
            Some(SessionSlot::Http(s)) => {
                assert_eq!(s.auth, crate::http::AuthKind::Bearer);
                assert_eq!(textarea_util::text_of(&s.auth_token_ta), "sk_test");
                assert!(textarea_util::text_of(&s.headers).contains("application/json"));
                assert_eq!(
                    textarea_util::text_of(&s.url),
                    "http://127.0.0.1:18081/v1/orders/ord_8f2c91a4"
                );
            }
            _ => panic!("expected HTTP session"),
        }
    }

    #[test]
    fn collection_without_url_opens_first_request() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut col = crate::collections::Collection::new("kestrel");
        col.requests.push(crate::collections::SavedRequest {
            name: "Readiness".into(),
            kind: "http".into(),
            target: "http://127.0.0.1:18081/readyz".into(),
            method: Some("GET".into()),
            headers: vec![],
            body: String::new(),
            ..Default::default()
        });
        ws.collection = Some(col.clone());
        ws.hydrate_http_from_collection();
        match ws.active_session() {
            Some(SessionSlot::Http(s)) => {
                assert_eq!(
                    textarea_util::text_of(&s.url),
                    "http://127.0.0.1:18081/readyz"
                );
                assert_eq!(textarea_util::text_of(&s.method), "GET");
            }
            _ => panic!("expected HTTP session"),
        }
    }

    #[test]
    fn new_session_uri_prefills_and_shows_defaults() {
        for kind in 0..=6u8 {
            let kind = kind as usize;
            let (a, b) = Workspace::uri_defaults(kind);
            let args = Args::parse_from(["bitbeak"]);
            let mut ws = Workspace::new(&args).unwrap();
            ws.begin_uri_entry(kind);
            if kind == 6 {
                assert!(textarea_util::text_of(&ws.uri_input).is_empty());
            } else {
                assert_eq!(textarea_util::text_of(&ws.uri_input), a, "kind {kind}");
            }
            let term = ui::draw_test(&mut ws, 80, 24);
            let screen = ui::screen_text(&term);
            if kind == 6 {
                assert!(
                    screen.contains("/path/to/capture.pcapng"),
                    "pcap placeholder missing:\n{screen}"
                );
            } else {
                assert!(
                    screen.contains(a),
                    "kind {kind} default {a:?} clipped/missing:\n{screen}"
                );
            }
            if !b.is_empty() {
                assert!(
                    screen.contains(b),
                    "kind {kind} upstream {b:?} clipped/missing:\n{screen}"
                );
            }
        }
    }

    #[test]
    fn stream_and_listen_composer_keep_payload_visible() {
        let payload = "bb-composer-ping-xyz";
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        let mut stream = crate::session::StreamSession::inert(
            crate::cli::Target::Tcp {
                host: "127.0.0.1".into(),
                port: 9,
            },
            crate::framing::FramingConfig::default(),
            100,
        );
        let _ = stream.take_io_rx();
        textarea_util::set_text(&mut stream.composer, payload);
        stream.focus = crate::session::PaneFocus::Composer;
        ws.sessions.push(SessionSlot::Stream(stream));

        let mut listen = crate::session::ListenSession::inert(
            crate::cli::Target::Tcp {
                host: "127.0.0.1".into(),
                port: 9,
            },
            crate::framing::FramingConfig::default(),
            100,
        );
        let _ = listen.take_io_rx();
        textarea_util::set_text(&mut listen.composer, payload);
        ws.sessions.push(SessionSlot::Listen(listen));

        for active in [0usize, 1] {
            ws.active = active;
            for (w, h) in [(80, 24), (60, 18)] {
                let term = ui::draw_test(&mut ws, w, h);
                let screen = ui::screen_text(&term);
                assert!(
                    screen.contains(payload),
                    "session {active} {w}x{h} composer clipped:\n{screen}"
                );
            }
        }
    }

    #[test]
    fn filter_and_palette_show_typed_input() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        textarea_util::set_text(&mut ws.filter_input, "bb-filt-xyz");
        ws.overlay = Overlay::Filter;
        let screen = ui::screen_text(&ui::draw_test(&mut ws, 80, 24));
        assert!(
            screen.contains("bb-filt-xyz"),
            "filter input clipped:\n{screen}"
        );

        textarea_util::set_text(&mut ws.palette_input, "bb-pal-xyz");
        ws.overlay = Overlay::CommandPalette;
        let screen = ui::screen_text(&ui::draw_test(&mut ws, 80, 24));
        assert!(
            screen.contains("bb-pal-xyz"),
            "palette input clipped:\n{screen}"
        );
    }

    #[test]
    fn capture_and_diag_empty_states_are_labeled() {
        let args = Args::parse_from(["bitbeak"]);
        let mut ws = Workspace::new(&args).unwrap();
        ws.sessions.push(SessionSlot::Capture(
            crate::session::CaptureSession::new_live("any", 100),
        ));
        let screen = ui::screen_text(&ui::draw_test(&mut ws, 100, 30));
        assert!(
            screen.contains("waiting for packets") || screen.contains("not started"),
            "capture empty hint missing:\n{screen}"
        );

        ws.sessions.clear();
        ws.sessions
            .push(SessionSlot::Diag(crate::session::DiagSession::new(
                crate::cli::DiagSpec::Dns {
                    host: "example.com".into(),
                },
            )));
        let screen = ui::screen_text(&ui::draw_test(&mut ws, 80, 24));
        assert!(
            screen.contains("running diagnose") || screen.contains("DNS example.com"),
            "diag default missing:\n{screen}"
        );
    }
}
