//! UI rendering and overlays.

pub mod hitmap;
pub mod textarea_util;
pub mod theme;

use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use tui_textarea::TextArea;

use crate::cli::{parse_diag, parse_target};
use crate::dissect::coloring::color_for_packet;
use crate::frame::Frame as NetFrame;
use crate::inspect::{crc32, hex_dump, render_lines, InspectMode};
use crate::session::{CaptureSession, ConnStatus, HttpField, PaneFocus, SessionKind, SessionView};
use crate::ui::hitmap::{HitMap, HitTarget};
use crate::workspace::{FlashKind, Overlay, SessionSlot, Workspace};

const SPINNER: [char; 4] = ['⠋', '⠙', '⠹', '⠼'];

/// Draw the full workspace UI, filling `ws.hitmap` and returning a clone.
pub fn draw(frame: &mut Frame, ws: &mut Workspace) -> HitMap {
    let mut hits = HitMap::default();
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .split(area);

    let tick = ws.tick;
    draw_header(frame, chunks[0], ws, &mut hits);
    draw_body(frame, chunks[1], ws, tick, &mut hits);
    draw_toast(frame, chunks[2], ws);
    draw_footer(frame, chunks[3], ws, &mut hits);

    match ws.overlay {
        Overlay::None => {}
        Overlay::Help => draw_help(frame, area, &mut hits),
        Overlay::Quit => draw_quit(
            frame,
            area,
            ws.quit_yes,
            "quit",
            "Do you want to quit?",
            &mut hits,
        ),
        Overlay::CloseConfirm => draw_quit(
            frame,
            area,
            ws.close_yes,
            "close tab",
            "Close tab?",
            &mut hits,
        ),
        Overlay::NewSession => draw_new_session(frame, area, ws, &mut hits),
        Overlay::NewSessionUri { kind } => draw_new_session_uri(frame, area, ws, kind, &mut hits),
        Overlay::Filter => draw_filter(frame, area, ws, &mut hits),
        Overlay::Collections => draw_collections(frame, area, ws, &mut hits),
        Overlay::Bench => draw_bench(frame, area, ws, &mut hits),
        Overlay::Fuzz => draw_fuzz(frame, area, ws, &mut hits),
        Overlay::CommandPalette => draw_palette(frame, area, ws, &mut hits),
        Overlay::FollowStream
        | Overlay::Conversations
        | Overlay::Endpoints
        | Overlay::Hierarchy
        | Overlay::Expert
        | Overlay::Keylog => draw_capture_overlay(frame, area, ws, &mut hits),
        Overlay::TestsEdit | Overlay::PreScriptEdit => draw_edit_overlay(frame, area, ws, &mut hits),
    }

    ws.hitmap = hits.clone();
    hits
}

fn draw_header(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let env_bit = ws
        .collection
        .as_ref()
        .map(|c| format!(" · {}/{}", c.name, c.active_env_name()))
        .unwrap_or_default();
    let title = format!(" bitbeak v0.1{env_bit} ");
    let inner = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(Span::styled(title.clone(), theme::title()))
        .inner(area);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title(Span::styled(title, theme::title())),
        area,
    );

    let mut x = inner.x;
    let y = inner.y;
    let max_x = inner.x.saturating_add(inner.width);

    if ws.sessions.is_empty() {
        let text = " (no sessions — F2 / [+] New) ";
        frame.render_widget(
            Paragraph::new(Span::styled(text, theme::dim())),
            Rect::new(x, y, (text.len() as u16).min(inner.width), 1),
        );
    } else {
        for (i, s) in ws.sessions.iter().enumerate() {
            let label = format!(" {} ", s.short_tab(i));
            let w = label.chars().count() as u16;
            if x.saturating_add(w) > max_x {
                break;
            }
            let style = if i == ws.active {
                theme::accent()
            } else {
                theme::dim()
            };
            let rect = Rect::new(x, y, w, 1);
            frame.render_widget(Paragraph::new(Span::styled(label, style)), rect);
            hits.push(rect, HitTarget::Tab(i));
            x = x.saturating_add(w);
            if x < max_x {
                let div = "│";
                frame.render_widget(
                    Paragraph::new(Span::styled(div, theme::dim())),
                    Rect::new(x, y, 1, 1),
                );
                x = x.saturating_add(1);
            }
        }
    }

    let plus = " [+] ";
    let pw = plus.len() as u16;
    if x.saturating_add(pw) <= max_x {
        let rect = Rect::new(x, y, pw, 1);
        frame.render_widget(Paragraph::new(Span::styled(plus, theme::accent())), rect);
        hits.push(rect, HitTarget::NewTab);
    }
}

fn draw_body(frame: &mut Frame, area: Rect, ws: &mut Workspace, tick: u64, hits: &mut HitMap) {
    let Some(_) = ws.active_session() else {
        let p = Paragraph::new(
            "Open a session with F2 or click [+].\n\nExamples:\n  tcp://127.0.0.1:9090\n  https://example.com\n  unix:///tmp/app.sock\n  ws://localhost:8080/v1",
        )
        .style(theme::value())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" welcome ", theme::title())),
        );
        frame.render_widget(p, area);
        return;
    };

    match ws.active {
        i if ws.sessions.get(i).is_some() => match &mut ws.sessions[i] {
            SessionSlot::Stream(s) => draw_stream(frame, area, s, tick, hits),
            SessionSlot::Http(s) => draw_http(frame, area, s, tick, hits),
            SessionSlot::Listen(s) => draw_listen(frame, area, s, tick, hits),
            SessionSlot::Proxy(s) => draw_proxy(frame, area, s, tick, hits),
            SessionSlot::Diag(s) => draw_diag(frame, area, s, tick, hits),
            SessionSlot::Capture(s) => draw_capture(frame, area, s, tick, hits),
        },
        _ => {}
    }
}

fn status_line(
    target: &str,
    status: ConnStatus,
    frames: usize,
    msg: &str,
    tick: u64,
) -> Line<'static> {
    let mut status_label = status.label().to_string();
    if status == ConnStatus::Connecting {
        let spin = SPINNER[(tick % 4) as usize];
        status_label = format!("{spin} {status_label}");
    }
    Line::from(vec![
        Span::styled(" Target: ", theme::label()),
        Span::styled(target.to_string(), theme::value()),
        Span::styled(" │ Status: ", theme::label()),
        Span::styled(status_label, theme::conn_status(status)),
        Span::styled(format!(" │ Frames: {frames} "), theme::label()),
        Span::styled(msg.to_string(), theme::dim()),
    ])
}

fn draw_stream(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::StreamSession,
    tick: u64,
    hits: &mut HitMap,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(6),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(status_line(
            &s.target.display(),
            s.status,
            s.frames.len(),
            &s.status_msg,
            tick,
        )),
        chunks[0],
    );

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let filtered = s.frames.filtered(&s.filter);
    let total = s.frames.len();
    // Broad pane hits first; row / pill / Send hits registered afterward win.
    hits.push(mid[0], HitTarget::Focus(PaneFocus::Log));
    hits.push(mid[1], HitTarget::Focus(PaneFocus::Inspector));
    hits.push(chunks[2], HitTarget::Focus(PaneFocus::Composer));
    draw_frame_log(
        frame,
        mid[0],
        &filtered,
        total,
        &s.filter,
        s.selected,
        s.follow,
        s.focus == PaneFocus::Log,
        " STREAM LOG ",
        empty_log_hint(s.status, false),
        hits,
    );

    let selected_frame = filtered.get(s.selected).copied();
    draw_inspector(
        frame,
        mid[1],
        selected_frame,
        s.inspect,
        s.focus == PaneFocus::Inspector,
        hits,
    );

    draw_composer(
        frame,
        chunks[2],
        &mut s.composer,
        s.composer_mode,
        s.focus == PaneFocus::Composer,
        " COMPOSER / REPLAY ",
        None,
        hits,
    );
}

fn draw_listen(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::ListenSession,
    tick: u64,
    hits: &mut HitMap,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(6),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(status_line(
            &s.target.display(),
            s.status,
            s.frames.len(),
            &format!(
                "{} · clients {} · broadcast {}",
                s.status_msg,
                s.clients.len(),
                if s.broadcast { "ON" } else { "off" }
            ),
            tick,
        )),
        chunks[0],
    );

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(43),
            Constraint::Percentage(35),
        ])
        .split(chunks[1]);

    let client_items: Vec<ListItem> = if s.clients.is_empty() {
        vec![ListItem::new(Span::styled(
            format!(" no clients yet — connect to {}", s.target.display()),
            theme::dim(),
        ))]
    } else {
        s.clients
            .iter()
            .map(|c| {
                let mark = if Some(c.id) == s.selected_client {
                    "*"
                } else {
                    " "
                };
                let style = if Some(c.id) == s.selected_client {
                    theme::selected(theme::value())
                } else {
                    theme::value()
                };
                ListItem::new(Span::styled(
                    format!(
                        "{mark} #{} {} in:{} out:{}",
                        c.id, c.peer, c.bytes_in, c.bytes_out
                    ),
                    style,
                ))
            })
            .collect()
    };
    hits.push(mid[0], HitTarget::Focus(PaneFocus::Clients));
    hits.push(mid[1], HitTarget::Focus(PaneFocus::Log));
    hits.push(mid[2], HitTarget::Focus(PaneFocus::Inspector));
    hits.push(chunks[2], HitTarget::Focus(PaneFocus::Composer));

    frame.render_widget(
        List::new(client_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if s.focus == PaneFocus::Clients {
                    theme::accent()
                } else {
                    theme::border()
                })
                .title(Span::styled(" CLIENTS ", theme::title())),
        ),
        mid[0],
    );

    let filtered = s.frames.filtered(&s.filter);
    let total = s.frames.len();
    draw_frame_log(
        frame,
        mid[1],
        &filtered,
        total,
        &s.filter,
        s.selected,
        s.follow,
        s.focus == PaneFocus::Log,
        " STREAM LOG ",
        empty_log_hint(s.status, true),
        hits,
    );

    draw_inspector(
        frame,
        mid[2],
        filtered.get(s.selected).copied(),
        s.inspect,
        s.focus == PaneFocus::Inspector,
        hits,
    );

    draw_composer(
        frame,
        chunks[2],
        &mut s.composer,
        s.composer_mode,
        s.focus == PaneFocus::Composer,
        " COMPOSER ",
        Some(s.broadcast),
        hits,
    );
}

fn draw_proxy(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::ProxySession,
    tick: u64,
    hits: &mut HitMap,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(6),
        ])
        .split(area);
    let mitm = if s.tls_intercept {
        " · MITM/HTTP1.1"
    } else {
        ""
    };
    frame.render_widget(
        Paragraph::new(status_line(
            &format!("{}{mitm}", s.target_display()),
            s.status,
            s.frames.len(),
            &s.status_msg,
            tick,
        )),
        chunks[0],
    );
    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);
    let filtered = s.frames.filtered(&s.filter);
    let total = s.frames.len();
    hits.push(mid[0], HitTarget::Focus(PaneFocus::Log));
    hits.push(mid[1], HitTarget::Focus(PaneFocus::Inspector));
    hits.push(chunks[2], HitTarget::Focus(PaneFocus::Composer));
    draw_frame_log(
        frame,
        mid[0],
        &filtered,
        total,
        &s.filter,
        s.selected,
        s.follow,
        s.focus == PaneFocus::Log,
        " PROXY FLOWS ",
        if s.tls_intercept {
            "waiting for HTTPS · install CA (: ca-path) · HTTP/1.1 only"
        } else {
            "waiting for traffic · Tab → composer · F6 inject"
        },
        hits,
    );
    draw_inspector(
        frame,
        mid[1],
        filtered.get(s.selected).copied(),
        s.inspect,
        s.focus == PaneFocus::Inspector,
        hits,
    );
    s.sync_composer_style();
    paint_textarea(
        frame,
        chunks[2],
        &mut s.composer,
        s.focus == PaneFocus::Composer,
        Some(Line::from(Span::styled(
            " COMPOSER inject→upstream (Enter send) ",
            theme::title(),
        ))),
    );
}

fn draw_http(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::HttpSession,
    tick: u64,
    hits: &mut HitMap,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(8),
        ])
        .split(area);

    let cookie = if s.cookies.enabled {
        "cookies:on"
    } else {
        "cookies:off"
    };
    let tests_badge = if s.tests.is_empty() {
        String::new()
    } else {
        format!(" · tests:{}", s.tests.len())
    };
    let script_badge = if s.pre_script.trim().is_empty() {
        ""
    } else {
        " · script:on"
    };
    frame.render_widget(
        Paragraph::new(status_line(
            &format!(
                "{} · {} · {:?} · {cookie}{tests_badge}{script_badge}",
                textarea_util::text_of(&s.url),
                s.auth_label(),
                s.body_mode
            ),
            s.status,
            s.frames.len(),
            &s.status_msg,
            tick,
        )),
        chunks[0],
    );

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(chunks[1]);

    draw_http_request(frame, mid[0], s, hits);

    let mut right: Vec<Line<'static>> = s
        .response_summary_lines()
        .into_iter()
        .map(|(l, kind)| {
            let style = match kind {
                crate::session::ResponseLineKind::Pass => theme::success(),
                crate::session::ResponseLineKind::Fail => theme::danger(),
                crate::session::ResponseLineKind::Redirect => theme::blue(),
                crate::session::ResponseLineKind::Section => theme::label(),
                crate::session::ResponseLineKind::Normal => theme::value(),
            };
            Line::from(Span::styled(l, style))
        })
        .collect();
    if let Some(fr) = s.frames.get(s.selected) {
        let (dump, err) = render_lines(
            s.inspect,
            &fr.payload,
            mid[1].height.saturating_sub(10) as usize,
        );
        right.push(Line::from(""));
        right.push(Line::from(Span::styled(
            format!("── body ({}) ──", s.inspect.label()),
            theme::label(),
        )));
        if let Some(e) = err {
            right.push(Line::from(Span::styled(e, theme::danger())));
        }
        right.extend(dump);
    }
    frame.render_widget(
        Paragraph::new(right).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" RESPONSE ", theme::title())),
        ),
        mid[1],
    );

    let hist_border = if s.focus == PaneFocus::History {
        theme::accent()
    } else {
        theme::border()
    };
    let visible = 6usize;
    if s.history_cursor < s.history_scroll {
        s.history_scroll = s.history_cursor;
    }
    if s.history_cursor >= s.history_scroll + visible {
        s.history_scroll = s.history_cursor + 1 - visible;
    }
    let hist: Vec<ListItem> = s
        .history
        .iter()
        .enumerate()
        .skip(s.history_scroll)
        .take(visible)
        .map(|(i, h)| {
            let style = if s.focus == PaneFocus::History && i == s.history_cursor {
                theme::selected(theme::accent())
            } else {
                theme::value()
            };
            ListItem::new(Span::styled(format!(" {h}"), style))
        })
        .collect();
    let hist_area = chunks[2];
    frame.render_widget(
        List::new(hist).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(hist_border)
                .title(Span::styled(
                    " HISTORY · Enter replay · click row ",
                    theme::title(),
                )),
        ),
        hist_area,
    );
    hits.push(hist_area, HitTarget::Focus(PaneFocus::History));
    let inner_y = hist_area.y.saturating_add(1);
    for (vis_i, abs_i) in
        (s.history_scroll..s.history.len().min(s.history_scroll + visible)).enumerate()
    {
        let row = Rect::new(
            hist_area.x.saturating_add(1),
            inner_y.saturating_add(vis_i as u16),
            hist_area.width.saturating_sub(2),
            1,
        );
        hits.push(row, HitTarget::HistoryRow(abs_i));
    }
}

fn draw_http_request(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::HttpSession,
    hits: &mut HitMap,
) {
    let border = if s.focus == PaneFocus::Form {
        theme::accent()
    } else {
        theme::border()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            format!(" REQUEST [{}]  [ Send ] ", s.field_hint()),
            theme::title(),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let send_w = 8u16;
    if area.width > send_w + 2 {
        hits.push(
            Rect::new(
                area.x + area.width.saturating_sub(send_w + 1),
                area.y,
                send_w,
                1,
            ),
            HitTarget::Send,
        );
    }

    let auth_h = match s.auth {
        crate::http::AuthKind::None => 2u16,
        crate::http::AuthKind::Bearer => 4,
        crate::http::AuthKind::Basic => 5,
        crate::http::AuthKind::ApiKeyHeader | crate::http::AuthKind::ApiKeyQuery => 5,
        crate::http::AuthKind::OAuth2 => 16,
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(auth_h),
            Constraint::Percentage(30),
            Constraint::Min(3),
        ])
        .split(inner);

    draw_labeled_textarea(
        frame,
        rows[0],
        "Method",
        &mut s.method,
        s.field == HttpField::Method && s.focus == PaneFocus::Form,
        HttpField::Method,
        hits,
    );
    draw_labeled_textarea(
        frame,
        rows[1],
        "URL",
        &mut s.url,
        s.field == HttpField::Url && s.focus == PaneFocus::Form,
        HttpField::Url,
        hits,
    );

    draw_http_auth(frame, rows[2], s, hits);

    draw_labeled_textarea(
        frame,
        rows[3],
        "Headers",
        &mut s.headers,
        s.field == HttpField::Headers && s.focus == PaneFocus::Form,
        HttpField::Headers,
        hits,
    );

    if matches!(
        s.body_mode,
        crate::http::BodyMode::UrlEncoded | crate::http::BodyMode::Multipart
    ) {
        draw_http_form(frame, rows[4], s, hits);
    } else if matches!(s.body_mode, crate::http::BodyMode::GraphQL) {
        let halves = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(35),
                Constraint::Percentage(15),
            ])
            .split(rows[4]);
        draw_labeled_textarea(
            frame,
            halves[0],
            "GraphQL query",
            &mut s.body,
            s.field == HttpField::Body && s.focus == PaneFocus::Form,
            HttpField::Body,
            hits,
        );
        draw_labeled_textarea(
            frame,
            halves[1],
            "Variables (JSON)",
            &mut s.graphql_vars_ta,
            s.field == HttpField::GraphqlVars && s.focus == PaneFocus::Form,
            HttpField::GraphqlVars,
            hits,
        );
        draw_labeled_textarea(
            frame,
            halves[2],
            "Operation name",
            &mut s.graphql_op_ta,
            s.field == HttpField::GraphqlOp && s.focus == PaneFocus::Form,
            HttpField::GraphqlOp,
            hits,
        );
    } else {
        textarea_util::set_placeholder(&mut s.body, "request body");
        draw_labeled_textarea(
            frame,
            rows[4],
            "Body (raw) · :body-mode for forms/GraphQL",
            &mut s.body,
            s.field == HttpField::Body && s.focus == PaneFocus::Form,
            HttpField::Body,
            hits,
        );
    }
}

fn draw_http_auth(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::HttpSession,
    hits: &mut HitMap,
) {
    let kind_focused = s.field == HttpField::AuthKind && s.focus == PaneFocus::Form;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);
    let kind_style = if kind_focused {
        theme::accent()
    } else {
        theme::label()
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(" Auth [{}] · Enter cycles", s.auth_label()),
            kind_style,
        )),
        chunks[0],
    );
    hits.push(chunks[0], HitTarget::HttpField(HttpField::AuthKind));

    match s.auth {
        crate::http::AuthKind::None => {
            frame.render_widget(
                Paragraph::new(Span::styled(" (no credentials)", theme::dim())),
                chunks[1],
            );
        }
        crate::http::AuthKind::Bearer => {
            draw_labeled_textarea(
                frame,
                chunks[1],
                "Bearer token",
                &mut s.auth_token_ta,
                s.field == HttpField::AuthToken && s.focus == PaneFocus::Form,
                HttpField::AuthToken,
                hits,
            );
        }
        crate::http::AuthKind::Basic => {
            let halves = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[1]);
            draw_labeled_textarea(
                frame,
                halves[0],
                "Username",
                &mut s.auth_user_ta,
                s.field == HttpField::AuthUser && s.focus == PaneFocus::Form,
                HttpField::AuthUser,
                hits,
            );
            draw_labeled_textarea(
                frame,
                halves[1],
                "Password",
                &mut s.auth_pass_ta,
                s.field == HttpField::AuthPass && s.focus == PaneFocus::Form,
                HttpField::AuthPass,
                hits,
            );
        }
        crate::http::AuthKind::OAuth2 => {
            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(2),
                ])
                .split(chunks[1]);
            draw_labeled_textarea(
                frame,
                parts[0],
                "OAuth client_id",
                &mut s.auth_user_ta,
                s.field == HttpField::AuthUser && s.focus == PaneFocus::Form,
                HttpField::AuthUser,
                hits,
            );
            draw_labeled_textarea(
                frame,
                parts[1],
                "OAuth client_secret",
                &mut s.auth_pass_ta,
                s.field == HttpField::AuthPass && s.focus == PaneFocus::Form,
                HttpField::AuthPass,
                hits,
            );
            draw_labeled_textarea(
                frame,
                parts[2],
                "Authorize URL",
                &mut s.auth_key_ta,
                s.field == HttpField::AuthKey && s.focus == PaneFocus::Form,
                HttpField::AuthKey,
                hits,
            );
            draw_labeled_textarea(
                frame,
                parts[3],
                "Token URL",
                &mut s.auth_value_ta,
                s.field == HttpField::AuthValue && s.focus == PaneFocus::Form,
                HttpField::AuthValue,
                hits,
            );
            draw_labeled_textarea(
                frame,
                parts[4],
                "Access token (:oauth to fetch)",
                &mut s.auth_token_ta,
                s.field == HttpField::AuthToken && s.focus == PaneFocus::Form,
                HttpField::AuthToken,
                hits,
            );
        }
        crate::http::AuthKind::ApiKeyHeader | crate::http::AuthKind::ApiKeyQuery => {
            let halves = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[1]);
            draw_labeled_textarea(
                frame,
                halves[0],
                "API key name",
                &mut s.auth_key_ta,
                s.field == HttpField::AuthKey && s.focus == PaneFocus::Form,
                HttpField::AuthKey,
                hits,
            );
            draw_labeled_textarea(
                frame,
                halves[1],
                "API key value",
                &mut s.auth_value_ta,
                s.field == HttpField::AuthValue && s.focus == PaneFocus::Form,
                HttpField::AuthValue,
                hits,
            );
        }
    }
}

fn draw_http_form(
    frame: &mut Frame,
    area: Rect,
    s: &mut crate::session::HttpSession,
    hits: &mut HitMap,
) {
    let mode = match s.body_mode {
        crate::http::BodyMode::UrlEncoded => "urlencoded",
        crate::http::BodyMode::Multipart => "multipart",
        _ => "form",
    };
    let focused = s.field == HttpField::Form && s.focus == PaneFocus::Form;
    let border = if focused {
        theme::accent()
    } else {
        theme::border()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(Span::styled(
            format!(
                " Form ({mode}) row {}/{} · ^N add · ^X del · Tab cell ",
                if s.form_fields.is_empty() {
                    0
                } else {
                    s.form_row + 1
                },
                s.form_fields.len()
            ),
            theme::title(),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    hits.push(area, HitTarget::HttpField(HttpField::Form));

    let cols = if matches!(s.body_mode, crate::http::BodyMode::Multipart) {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(35),
                Constraint::Percentage(35),
            ])
            .split(inner)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(inner)
    };

    draw_mini_ta(
        frame,
        cols[0],
        "key",
        &mut s.form_key_ta,
        focused && s.form_cell == crate::session::FormCell::Key,
    );
    draw_mini_ta(
        frame,
        cols[1],
        "value",
        &mut s.form_value_ta,
        focused && s.form_cell == crate::session::FormCell::Value,
    );
    if cols.len() > 2 {
        draw_mini_ta(
            frame,
            cols[2],
            "file",
            &mut s.form_file_ta,
            focused && s.form_cell == crate::session::FormCell::File,
        );
    }
}

fn draw_mini_ta(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    ta: &mut TextArea<'static>,
    focused: bool,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    draw_textarea_field(frame, area, label, ta, focused);
}

fn draw_labeled_textarea(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    ta: &mut TextArea<'static>,
    focused: bool,
    field: HttpField,
    hits: &mut HitMap,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let value = draw_textarea_field(frame, area, label, ta, focused);
    hits.push(value, HitTarget::HttpField(field));
}

/// Label + editor. Full boxes need 3+ rows of editor; shorter areas drop the
/// borders so Method/URL stay readable (a 1-row box had no inner height).
fn draw_textarea_field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    ta: &mut TextArea<'static>,
    focused: bool,
) -> Rect {
    let value_area = if area.height == 1 {
        area
    } else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(1)])
            .split(area);
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {label}"), theme::label())),
            chunks[0],
        );
        chunks[1]
    };

    style_textarea(ta, focused, value_area.height < 3, None);
    frame.render_widget(&*ta, value_area);
    value_area
}

fn style_textarea(
    ta: &mut TextArea<'static>,
    focused: bool,
    compact: bool,
    title: Option<Line<'static>>,
) {
    ta.set_block(textarea_block(focused, compact, title));
    if focused {
        textarea_util::style_focused(ta);
    } else {
        textarea_util::style_unfocused(ta);
    }
}

fn textarea_block(focused: bool, compact: bool, title: Option<Line<'static>>) -> Block<'static> {
    let border = if focused {
        theme::accent()
    } else {
        theme::border()
    };
    let mut block = if compact {
        if focused {
            Block::default().borders(Borders::LEFT).border_style(border)
        } else {
            Block::default()
        }
    } else {
        Block::default().borders(Borders::ALL).border_style(border)
    };
    if let Some(title) = title {
        block = block.title(title);
    }
    block
}

fn paint_textarea(
    frame: &mut Frame,
    area: Rect,
    ta: &mut TextArea<'static>,
    focused: bool,
    title: Option<Line<'static>>,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    style_textarea(ta, focused, area.height < 3, title);
    frame.render_widget(&*ta, area);
}

fn packet_wall_hms(wall: SystemTime) -> String {
    wall.duration_since(UNIX_EPOCH)
        .map(|d| {
            let secs = d.as_secs();
            let h = (secs / 3600) % 24;
            let m = (secs / 60) % 60;
            let s = secs % 60;
            let ms = d.subsec_millis();
            format!("{h:02}:{m:02}:{s:02}.{ms:03}")
        })
        .unwrap_or_else(|_| "??:??:??.???".into())
}

fn io_sparkline(series: &[u64], width: usize) -> String {
    const BARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if series.is_empty() || width == 0 {
        return String::new();
    }
    let max = series.iter().copied().max().unwrap_or(1).max(1);
    let step = (series.len() as f64 / width as f64).max(1.0);
    let mut out = String::new();
    for i in 0..width {
        let idx = ((i as f64) * step) as usize;
        let v = series.get(idx).copied().unwrap_or(0);
        let bi = ((v as f64 / max as f64) * (BARS.len() - 1) as f64) as usize;
        out.push(BARS[bi.min(BARS.len() - 1)]);
    }
    out
}

fn draw_capture(
    frame: &mut Frame,
    area: Rect,
    s: &mut CaptureSession,
    tick: u64,
    hits: &mut HitMap,
) {
    let filtered = s.filtered_indices();
    let total = s.store.len();
    let spark_w = area.width.saturating_sub(40).max(8) as usize;
    let spark = io_sparkline(&s.stats.io.packet_series(), spark_w);
    let cap_badge = match s.source {
        crate::session::CaptureSource::File => Span::styled(" ■ FILE ", theme::blue()),
        _ if s.capturing => Span::styled(" ● LIVE ", theme::success()),
        _ => Span::styled(" ○ stopped ", theme::dim()),
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);

    let mut status = status_line(&s.title_iface, s.status, s.store.len(), &s.status_msg, tick);
    status
        .spans
        .push(Span::styled(format!(" │ {spark} "), theme::dim()));
    status.spans.push(cap_badge);
    if !s.capture_filter_str.is_empty() {
        let mode = if s.filter_kernel_bpf {
            "kernel BPF"
        } else {
            "userspace"
        };
        status.spans.push(Span::styled(
            format!(" · cfilter:{mode}"),
            theme::dim(),
        ));
    }
    frame.render_widget(Paragraph::new(status), chunks[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(42),
            Constraint::Percentage(33),
            Constraint::Percentage(25),
        ])
        .split(chunks[1]);

    hits.push(mid[0], HitTarget::Focus(PaneFocus::Log));
    hits.push(mid[1], HitTarget::Focus(PaneFocus::Tree));
    hits.push(mid[2], HitTarget::Focus(PaneFocus::Hex));

    draw_capture_packet_list(frame, mid[0], s, &filtered, total, hits);
    draw_capture_tree(frame, mid[1], s, hits);
    draw_capture_hex(frame, mid[2], s, hits);
}

fn draw_capture_packet_list(
    frame: &mut Frame,
    area: Rect,
    s: &CaptureSession,
    filtered: &[usize],
    total: usize,
    hits: &mut HitMap,
) {
    let height = area.height.saturating_sub(2) as usize;
    let sel = if filtered.is_empty() {
        0
    } else {
        s.selected.min(filtered.len() - 1)
    };
    let scroll = if filtered.is_empty() {
        0
    } else if s.follow {
        filtered.len().saturating_sub(height.max(1))
    } else {
        sel.saturating_sub(height.saturating_sub(1) / 2)
            .min(filtered.len().saturating_sub(height.max(1)))
    };

    let mut items = vec![ListItem::new(Line::from(Span::styled(
        format!(
            "{:>4} │ {:12} │ {:>18} │ {:>18} │ {:>6} │ {:>5} │ Info",
            "No", "Time", "Source", "Destination", "Proto", "Len"
        ),
        theme::header(),
    )))];

    if filtered.is_empty() {
        let empty_msg = if let Some(err) = &s.last_error {
            format!("  capture error: {err}")
        } else if s.status == ConnStatus::Error {
            format!("  open failed — {}", crate::capture::backend::capture_hint())
        } else if s.source == crate::session::CaptureSource::File {
            if !s.display_filter_str.is_empty() {
                format!(
                    "  filter empty — display filter ({}) matches nothing",
                    s.display_filter_str
                )
            } else {
                "  empty capture file".into()
            }
        } else if !s.capturing && s.source == crate::session::CaptureSource::Live {
            format!(
                "  not started — F6 to capture · {}",
                crate::capture::backend::capture_hint()
            )
        } else if s.capturing && !s.capture_filter_str.is_empty() {
            format!(
                "  capturing — no packets match filter ({})",
                s.capture_filter_str
            )
        } else if s.capturing {
            "  capturing — quiet (waiting for packets)".into()
        } else if !s.display_filter_str.is_empty() {
            format!(
                "  filter empty — display filter ({}) matches nothing",
                s.display_filter_str
            )
        } else {
            "  waiting for packets — F6 start/stop capture".into()
        };
        items.push(ListItem::new(Line::from(Span::styled(
            empty_msg,
            theme::dim(),
        ))));
    } else {
        let row_budget = height.saturating_sub(1);
        for (vis_i, &store_i) in filtered.iter().enumerate().skip(scroll).take(row_budget) {
            let Some(pkt) = s.store.get(store_i) else {
                continue;
            };
            let style = if vis_i == sel {
                theme::selected(color_for_packet(pkt))
            } else {
                color_for_packet(pkt)
            };
            let marker = if vis_i == sel { ">" } else { " " };
            let line = Line::from(vec![
                Span::styled(format!("{marker}{:>3} │ ", pkt.id), style),
                Span::styled(format!("{:12} │ ", packet_wall_hms(pkt.wall)), theme::dim()),
                Span::styled(
                    format!(
                        "{:>18} │ ",
                        truncate_field(&s.names.format_addr(&pkt.summary.src), 18)
                    ),
                    style,
                ),
                Span::styled(
                    format!(
                        "{:>18} │ ",
                        truncate_field(&s.names.format_addr(&pkt.summary.dst), 18)
                    ),
                    style,
                ),
                Span::styled(
                    format!("{:>6} │ ", truncate_field(&pkt.summary.protocol, 6)),
                    style,
                ),
                Span::styled(format!("{:>4} │ ", pkt.summary.len), style),
                Span::styled(truncate_field(&pkt.summary.info, 32), style),
            ]);
            items.push(ListItem::new(line));

            let row_y = area.y + 1 + 1 + (vis_i.saturating_sub(scroll) as u16);
            if row_y < area.y.saturating_add(area.height.saturating_sub(1)) {
                hits.push(
                    Rect::new(area.x + 1, row_y, area.width.saturating_sub(2), 1),
                    HitTarget::LogRow(vis_i),
                );
            }
        }
    }

    let follow_badge = if s.follow {
        Span::styled(" ▼ live ", theme::success())
    } else {
        Span::styled(" ⏸ paused ", theme::dim())
    };
    let mut title_spans = vec![Span::styled(" PACKETS ", theme::title()), follow_badge];
    if !s.display_filter_str.is_empty() {
        title_spans.push(Span::styled(
            format!(
                " /{} ({} of {total}) ",
                s.display_filter_str,
                filtered.len()
            ),
            theme::header(),
        ));
    }

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if s.focus == PaneFocus::Log {
                    theme::accent()
                } else {
                    theme::border()
                })
                .title(Line::from(title_spans)),
        ),
        area,
    );
}

fn truncate_field(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn draw_capture_tree(frame: &mut Frame, area: Rect, s: &mut CaptureSession, _hits: &mut HitMap) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let idx = s.filtered_indices();
    if idx.is_empty() {
        lines.push(Line::from(Span::styled("(no selection)", theme::dim())));
    } else if let Some(pkt) = s.store.get_mut(idx[s.selected.min(idx.len() - 1)]) {
        let tree = pkt.ensure_tree();
        let visible = tree.visible();
        let max_rows = area.height.saturating_sub(2) as usize;
        let sel = s.tree_selected.min(visible.len().saturating_sub(1));
        let scroll = sel.saturating_sub(max_rows.saturating_sub(1) / 2);
        for (i, (depth, node_idx)) in visible.iter().enumerate().skip(scroll).take(max_rows) {
            let Some(node) = tree.node(*node_idx) else {
                continue;
            };
            let indent = "  ".repeat(*depth);
            let style = if i == sel {
                theme::selected(theme::value())
            } else {
                theme::value()
            };
            lines.push(Line::from(Span::styled(
                format!("{indent}{}", node.display()),
                style,
            )));
        }
    } else {
        lines.push(Line::from(Span::styled("(no tree)", theme::dim())));
    }

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if s.focus == PaneFocus::Tree {
                    theme::accent()
                } else {
                    theme::border()
                })
                .title(Span::styled(" PROTOCOL TREE ", theme::title())),
        ),
        area,
    );
}

fn draw_capture_hex(frame: &mut Frame, area: Rect, s: &CaptureSession, _hits: &mut HitMap) {
    let max_lines = area.height.saturating_sub(2) as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(pkt) = s.visible_packet() {
        let data = pkt.decrypted.as_ref().unwrap_or(&pkt.data);
        for l in hex_dump(data, max_lines.max(1)) {
            lines.push(Line::from(Span::styled(l, theme::value())));
        }
        lines.push(Line::from(Span::styled(
            format!("{} bytes", data.len()),
            theme::label(),
        )));
    } else {
        lines.push(Line::from(Span::styled("(no selection)", theme::dim())));
    }

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if s.focus == PaneFocus::Hex {
                    theme::accent()
                } else {
                    theme::border()
                })
                .title(Span::styled(" HEX ", theme::title())),
        ),
        area,
    );
}

fn draw_capture_overlay(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let Some(SessionSlot::Capture(s)) = ws.active_session() else {
        return;
    };
    let (title, text) = match ws.overlay {
        Overlay::FollowStream => {
            if let Some(f) = &s.follow_view {
                let mut title = f.label.clone();
                if f.objects.iter().any(|o| o.is_request) {
                    title.push_str(" · r=replay HTTP");
                }
                title.push_str(" · Esc");
                (title, f.text.clone())
            } else {
                (" follow stream · Esc ".into(), "(no follow data)".into())
            }
        }
        Overlay::Conversations => {
            let mut t = String::new();
            for row in s.stats.conversations.rows() {
                t.push_str(&format!(
                    "{:?} {} ↔ {}  pkts {}  bytes {}\n",
                    row.kind,
                    row.addr_a,
                    row.addr_b,
                    row.packets(),
                    row.bytes()
                ));
            }
            if t.is_empty() {
                t = "(no conversations yet)".into();
            }
            (" conversations · ↑↓ Enter=filter · Esc ".into(), t)
        }
        Overlay::Endpoints => {
            let mut t = String::new();
            for row in s.stats.endpoints.rows() {
                t.push_str(&format!(
                    "{:?} {}  pkts {}  bytes {}\n",
                    row.kind, row.address, row.packets, row.bytes
                ));
            }
            if t.is_empty() {
                t = "(no endpoints yet)".into();
            }
            (" endpoints · Esc ".into(), t)
        }
        Overlay::Hierarchy => {
            let mut t = String::new();
            for (proto, pkts, bytes) in s.stats.hierarchy.rows() {
                t.push_str(&format!("{proto:>12}  {pkts:>6} pkts  {bytes:>8} bytes\n"));
            }
            if t.is_empty() {
                t = "(no protocols yet)".into();
            }
            (" protocol hierarchy · Esc ".into(), t)
        }
        Overlay::Expert => {
            let mut t = String::new();
            for pkt in s.store.iter() {
                for e in &pkt.expert {
                    t.push_str(&format!(
                        "#{} [{:?}] {}: {}\n",
                        pkt.id, e.severity, e.group, e.message
                    ));
                }
            }
            if t.is_empty() {
                t = "(no expert info)".into();
            }
            (" expert info · Esc ".into(), t)
        }
        Overlay::Keylog => {
            let t = match (&s.keylog_path, s.keylog.as_ref()) {
                (Some(p), Some(_)) => format!("loaded: {}\nTLS decrypt enabled", p.display()),
                (Some(p), None) => format!("path set but not loaded: {}", p.display()),
                _ => "no keylog — : keylog PATH or --keylog".into(),
            };
            (" keylog · Esc ".into(), t)
        }
        _ => return,
    };

    let h = area.height.clamp(10, 22);
    let w = area.width.clamp(50, 76);
    let r = centered(area, w, h);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(title, theme::title())),
        ),
        r,
    );
}

fn draw_diag(
    frame: &mut Frame,
    area: Rect,
    s: &crate::session::DiagSession,
    tick: u64,
    _hits: &mut HitMap,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);
    frame.render_widget(
        Paragraph::new(status_line(
            &s.target_display(),
            s.status,
            s.lines.len(),
            &s.status_msg,
            tick,
        )),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(s.lines.join("\n"))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::border())
                    .title(Span::styled(" DIAGNOSE ", theme::title())),
            ),
        chunks[1],
    );
}

fn empty_log_hint(status: ConnStatus, listen: bool) -> &'static str {
    if listen {
        "waiting for traffic — select a client and type in the composer"
    } else if matches!(status, ConnStatus::Disconnected | ConnStatus::Error) {
        "disconnected — F6 reconnect · type in composer and press Enter to send"
    } else {
        "waiting for traffic — type in the composer and press Enter"
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_frame_log(
    frame: &mut Frame,
    area: Rect,
    frames: &[&NetFrame],
    total: usize,
    filter: &str,
    selected: usize,
    follow: bool,
    focused: bool,
    title: &str,
    empty_hint: &str,
    hits: &mut HitMap,
) {
    let show_time = area.width >= 70;
    // Fixed columns: marker+id | [time |] dir | size | preview
    // " >123 │ " = 7, time "12:34:56.789 │ " = 15, dir "<- │ " = 6, size "9999B │ " = 8
    let fixed_cols: u16 = if show_time { 7 + 15 + 6 + 8 } else { 7 + 6 + 8 };
    let preview_w = area
        .width
        .saturating_sub(2)
        .saturating_sub(fixed_cols)
        .max(8) as usize;

    let height = area.height.saturating_sub(2) as usize;
    let sel = if frames.is_empty() {
        0
    } else {
        selected.min(frames.len() - 1)
    };
    let scroll = if frames.is_empty() {
        0
    } else if follow {
        frames.len().saturating_sub(height.max(1))
    } else {
        sel.saturating_sub(height.saturating_sub(1) / 2)
            .min(frames.len().saturating_sub(height.max(1)))
    };

    let mut items = Vec::new();
    if show_time {
        items.push(ListItem::new(Line::from(Span::styled(
            format!(
                "{:>4} │ {:12} │ {:3} │ {:>5} │ Preview",
                "#", "Time", "Dir", "Size"
            ),
            theme::header(),
        ))));
    } else {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("{:>4} │ {:3} │ {:>5} │ Preview", "#", "Dir", "Size"),
            theme::header(),
        ))));
    }

    if frames.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("  {empty_hint}"),
            theme::dim(),
        ))));
    } else {
        let row_budget = height.saturating_sub(1);
        for (i, f) in frames.iter().enumerate().skip(scroll).take(row_budget) {
            let style = if i == sel {
                theme::selected(theme::value())
            } else {
                theme::value()
            };
            let dir_style = if f.direction == crate::frame::Direction::In {
                theme::dir_in()
            } else {
                theme::dir_out()
            };
            let marker = if i == sel { ">" } else { " " };
            let mut spans = vec![Span::styled(format!("{marker}{:>3} │ ", f.id), style)];
            if show_time {
                spans.push(Span::styled(
                    format!("{:12} │ ", f.wall_hms_millis()),
                    theme::dim(),
                ));
            }
            spans.push(Span::styled(
                format!("{:3} │ ", f.direction.arrow()),
                dir_style,
            ));
            spans.push(Span::styled(format!("{:>4}B │ ", f.size()), style));
            spans.push(Span::styled(f.preview(preview_w), style));
            items.push(ListItem::new(Line::from(spans)));

            // Row hit: absolute filtered index
            let row_y = area.y + 1 + 1 + (i.saturating_sub(scroll) as u16); // border + header
            if row_y < area.y.saturating_add(area.height.saturating_sub(1)) {
                hits.push(
                    Rect::new(area.x + 1, row_y, area.width.saturating_sub(2), 1),
                    HitTarget::LogRow(i),
                );
            }
        }
    }

    let follow_badge = if follow {
        Span::styled(" ▼ live ", theme::success())
    } else {
        Span::styled(" ⏸ paused ", theme::dim())
    };
    let mut title_spans = vec![
        Span::styled(title.to_string(), theme::title()),
        follow_badge,
    ];
    if !filter.is_empty() {
        title_spans.push(Span::styled(
            format!(" /{filter} ({} of {total}) ", frames.len()),
            theme::header(),
        ));
    }

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focused {
                    theme::accent()
                } else {
                    theme::border()
                })
                .title(Line::from(title_spans)),
        ),
        area,
    );
}

fn draw_inspector(
    frame: &mut Frame,
    area: Rect,
    selected: Option<&NetFrame>,
    mode: InspectMode,
    focused: bool,
    hits: &mut HitMap,
) {
    let inner_h = area.height.saturating_sub(2);
    let mut lines: Vec<Line<'static>> = Vec::new();

    // Pills row with individual hit targets
    let mut pill_spans = Vec::new();
    let mut pill_x = area.x.saturating_add(1);
    let pill_y = area.y.saturating_add(1);
    for m in InspectMode::all() {
        let label = format!(" {} ", m.label());
        let w = label.chars().count() as u16;
        let style = if m == mode {
            theme::accent().add_modifier(Modifier::REVERSED)
        } else {
            theme::dim()
        };
        pill_spans.push(Span::styled(label.clone(), style));
        hits.push(Rect::new(pill_x, pill_y, w, 1), HitTarget::InspectMode(m));
        pill_x = pill_x.saturating_add(w);
    }
    lines.push(Line::from(pill_spans));

    let footer_reserve = 2usize;
    let max_dump = inner_h.saturating_sub(1 + footer_reserve as u16) as usize;

    if let Some(fr) = selected {
        let (dump, err) = render_lines(mode, &fr.payload, max_dump.max(1));
        if let Some(e) = err {
            lines.push(Line::from(Span::styled(e, theme::danger())));
        }
        lines.extend(dump);
        let peer = fr.peer.as_deref().unwrap_or("-");
        lines.push(Line::from(Span::styled(
            format!(
                "Length: {}  CRC32: 0x{:08X}  Dir: {}  peer: {}  {}",
                fr.payload.len(),
                crc32(&fr.payload),
                fr.direction.arrow(),
                peer,
                fr.wall_hms_millis()
            ),
            theme::label(),
        )));
        if let Some(meta) = &fr.meta {
            lines.push(Line::from(Span::styled(
                format!("meta: {meta}"),
                theme::dim(),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled("(no selection)", theme::dim())));
    }

    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focused {
                    theme::accent()
                } else {
                    theme::border()
                })
                .title(Span::styled(" INSPECTOR ", theme::title())),
        ),
        area,
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_composer(
    frame: &mut Frame,
    area: Rect,
    composer: &mut TextArea<'static>,
    mode: crate::composer::ComposerMode,
    focused: bool,
    title: &str,
    broadcast: Option<bool>,
    hits: &mut HitMap,
) {
    let mode_label = match mode {
        crate::composer::ComposerMode::Utf8 => "UTF-8",
        crate::composer::ComposerMode::Hex => "HEX",
    };

    let mut title_spans = vec![
        Span::styled(format!("{title} Mode: {mode_label} "), theme::title()),
        Span::styled("[ Send ]", theme::accent()),
    ];
    if let Some(on) = broadcast {
        let b = if on { "on" } else { "off" };
        title_spans.push(Span::raw(" "));
        title_spans.push(Span::styled(
            format!("[ Broadcast: {b} ]"),
            if on { theme::success() } else { theme::dim() },
        ));
    }

    textarea_util::set_placeholder(composer, "payload — Enter send");
    paint_textarea(
        frame,
        area,
        composer,
        focused,
        Some(Line::from(title_spans)),
    );

    // Approximate title-button hit targets on the top border row
    let send_label = "[ Send ]";
    let send_w = send_label.len() as u16;
    // Place Send near the right of the title area (after mode text)
    let send_x = area
        .x
        .saturating_add(title.len() as u16 + 14)
        .min(area.x.saturating_add(area.width.saturating_sub(send_w + 2)));
    hits.push(Rect::new(send_x, area.y, send_w, 1), HitTarget::Send);

    if let Some(on) = broadcast {
        let b = if on { "on" } else { "off" };
        let bl = format!("[ Broadcast: {b} ]");
        let bw = bl.len() as u16;
        let bx = send_x.saturating_add(send_w + 1);
        if bx.saturating_add(bw) <= area.x.saturating_add(area.width) {
            hits.push(Rect::new(bx, area.y, bw, 1), HitTarget::Broadcast);
        }
    }
}

fn draw_toast(frame: &mut Frame, area: Rect, ws: &Workspace) {
    if ws.status_flash.is_empty() {
        frame.render_widget(Paragraph::new(""), area);
        return;
    }
    let style = match ws.flash_kind {
        FlashKind::Ok => theme::toast_ok(),
        FlashKind::Err => theme::toast_err(),
        FlashKind::Info => theme::blue(),
    };
    frame.render_widget(
        Paragraph::new(Span::styled(format!(" {}", ws.status_flash), style)),
        area,
    );
}

fn draw_footer(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let kind = ws.active_session().map(|s| s.kind());

    let capture_active = matches!(kind, Some(SessionKind::Capture));
    let (f6_label, f6_dim) = match ws.active_session() {
        Some(SessionSlot::Capture(s))
            if s.source == crate::session::CaptureSource::File =>
        {
            ("—", true)
        }
        Some(SessionSlot::Capture(s)) => {
            if s.capturing {
                ("Stop", false)
            } else {
                ("Start", false)
            }
        }
        Some(SessionSlot::Http(_)) => ("Send", false),
        Some(SessionSlot::Stream(s)) if s.status == ConnStatus::Disconnected => ("Reconnect", false),
        Some(SessionSlot::Stream(s)) => ("Replay", s.frames.is_empty()),
        Some(SessionSlot::Listen(_)) => ("Send", false),
        Some(SessionSlot::Diag(_)) => ("Run", false),
        Some(SessionSlot::Proxy(_)) => ("Inject", false),
        None => ("Replay", true),
    };
    let f12_label = if capture_active { "Save" } else { "Pcap" };

    let f7_dim = !matches!(kind, Some(SessionKind::Http));
    let f11_dim = !matches!(kind, Some(SessionKind::Stream | SessionKind::Listen));

    let row1 = [
        (1u8, "F1", "Help", false),
        (2, "F2", "New", false),
        (3, "F3", "Prev", false),
        (4, "F4", "Next", false),
        (5, "F5", "Format", false),
        (6, "F6", f6_label, f6_dim),
        (7, "F7", "Bench", f7_dim),
        (8, "F8", "Filter", false),
    ];
    let row2 = [
        (9u8, "F9", "Collect", false),
        (10, "F10", "Quit", false),
        (11, "F11", "Fuzz", f11_dim),
        (12, "F12", f12_label, false),
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    render_footer_row(frame, chunks[0], &row1, hits);
    let mut spans2 = footer_spans(&row2);
    spans2.push(Span::styled(
        " Tab panes · Arrows · Esc · mouse · Ctrl+T/W",
        theme::dim(),
    ));
    // Register F9–F12 hits from row2 positions
    let mut x = chunks[1].x;
    for &(n, key, label, _dim) in &row2 {
        let key_s = format!(" {key} ");
        let lab_s = format!("{label} ");
        let w = (key_s.len() + lab_s.len()) as u16;
        hits.push(Rect::new(x, chunks[1].y, w, 1), HitTarget::FooterF(n));
        x = x.saturating_add(w);
    }
    frame.render_widget(Paragraph::new(Line::from(spans2)), chunks[1]);
}

fn footer_spans(items: &[(u8, &str, &str, bool)]) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for &(_, key, label, dim) in items {
        let (ks, ls) = if dim {
            (theme::disabled_key(), theme::disabled_label())
        } else {
            (theme::footer_key(), theme::footer_label())
        };
        spans.push(Span::styled(format!(" {key} "), ks));
        spans.push(Span::styled(format!("{label} "), ls));
    }
    spans
}

fn render_footer_row(
    frame: &mut Frame,
    area: Rect,
    items: &[(u8, &str, &str, bool)],
    hits: &mut HitMap,
) {
    let mut x = area.x;
    let mut spans = Vec::new();
    for &(n, key, label, dim) in items {
        let (ks, ls) = if dim {
            (theme::disabled_key(), theme::disabled_label())
        } else {
            (theme::footer_key(), theme::footer_label())
        };
        let key_s = format!(" {key} ");
        let lab_s = format!("{label} ");
        let w = (key_s.len() + lab_s.len()) as u16;
        spans.push(Span::styled(key_s, ks));
        spans.push(Span::styled(lab_s, ls));
        hits.push(Rect::new(x, area.y, w, 1), HitTarget::FooterF(n));
        x = x.saturating_add(w);
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w.min(area.width), h.min(area.height))
}

fn register_overlay_dismiss(area: Rect, dialog: Rect, hits: &mut HitMap) {
    // Four strips around the dialog
    if dialog.y > area.y {
        hits.push(
            Rect::new(area.x, area.y, area.width, dialog.y.saturating_sub(area.y)),
            HitTarget::OverlayDismiss,
        );
    }
    let below_y = dialog.y.saturating_add(dialog.height);
    if below_y < area.y.saturating_add(area.height) {
        hits.push(
            Rect::new(
                area.x,
                below_y,
                area.width,
                area.y.saturating_add(area.height).saturating_sub(below_y),
            ),
            HitTarget::OverlayDismiss,
        );
    }
    if dialog.x > area.x {
        hits.push(
            Rect::new(
                area.x,
                dialog.y,
                dialog.x.saturating_sub(area.x),
                dialog.height,
            ),
            HitTarget::OverlayDismiss,
        );
    }
    let right_x = dialog.x.saturating_add(dialog.width);
    if right_x < area.x.saturating_add(area.width) {
        hits.push(
            Rect::new(
                right_x,
                dialog.y,
                area.x.saturating_add(area.width).saturating_sub(right_x),
                dialog.height,
            ),
            HitTarget::OverlayDismiss,
        );
    }
}

fn draw_help(frame: &mut Frame, area: Rect, hits: &mut HitMap) {
    let h = if area.height < 24 { 18 } else { 22 };
    let r = centered(area, 78, h);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let resize = if area.height < 24 {
        "\n⚠ Terminal height < 24 — expand for full layout"
    } else {
        ""
    };
    let text = format!(
        "\
KEYS & MOUSE                              SHORTCUTS
F1–F12 match footer labels                j/k  move   g/G top/bottom
Arrows / PgUp / PgDn / Home / End         h/l  cycle inspector format
Tab / Shift+Tab cycle panes               /    filter (F8)
Enter activate / send                     q    quit prompt
Esc close overlay / clear filter          1-9  jump tab
Click tabs, [+], pills, Send, footer      :    command palette
Mouse wheel scrolls the log               Ctrl+T new   Ctrl+W close tab

Composer & HTTP are normal text fields — visible cursor, no vim modes.
HTTP: Enter sends (Method/URL/Headers); Body: Enter=newline, Ctrl+Enter=send
Stream: r / R replay selected frame · F6 Replay/Reconnect · composer Enter sends
Capture: F6 Start/Stop · : sniff (from HTTP) · follow-http · r = replay into HTTP
Proxy: Space/i TLS intercept on new · F6 Inject · : ca-path
: body-mode · auth · test · tests · grpc · oauth · pre-script · sniff
: history · gql-introspect · codegen NAME · rpcap host [iface] (experimental)
Hex escapes: \\x00 \\n \\r \\t \\\\   · Ctrl+M toggles hex mode
Listen: click [ Broadcast: on/off ] to toggle fan-out send
CLI: --codegen · --import
Glue loop: HTTP URL → : sniff → packet → : follow-http → r → Enter send{resize}"
    );
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" help ", theme::title())),
        ),
        r,
    );
}

fn draw_quit(
    frame: &mut Frame,
    area: Rect,
    yes: bool,
    title: &str,
    prompt: &str,
    hits: &mut HitMap,
) {
    let r = centered(area, 42, 7);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let yes_s = if yes {
        theme::accent().add_modifier(Modifier::REVERSED)
    } else {
        theme::value()
    };
    let no_s = if !yes {
        theme::accent().add_modifier(Modifier::REVERSED)
    } else {
        theme::value()
    };

    // Button rects (approximate positions from layout)
    let yes_rect = Rect::new(r.x + 5, r.y + 3, 7, 1);
    let no_rect = Rect::new(r.x + 18, r.y + 3, 6, 1);
    hits.push(yes_rect, HitTarget::QuitYes);
    hits.push(no_rect, HitTarget::QuitNo);

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(format!("  {prompt}"), theme::value())),
        Line::from(""),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("  Yes  ", yes_s),
            Span::raw("      "),
            Span::styled("  No  ", no_s),
        ]),
        Line::from(Span::styled(
            "  ←/→ switch · Enter confirm · Esc cancel",
            theme::dim(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(format!(" {title} "), theme::title())),
        ),
        r,
    );
}

fn draw_new_session(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let r = centered(area, 56, 16);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let inner = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(Span::styled(
            " new session — Enter, then type a URI ",
            theme::title(),
        ))
        .inner(r);

    let items: Vec<ListItem> = Workspace::NEW_KINDS
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let style = if i == ws.new_session_cursor {
                theme::selected(theme::accent())
            } else {
                theme::value()
            };
            ListItem::new(Span::styled(format!("  {k}"), style))
        })
        .collect();

    for i in 0..Workspace::NEW_KINDS.len() {
        let row = Rect::new(inner.x, inner.y.saturating_add(i as u16), inner.width, 1);
        hits.push(row, HitTarget::NewKind(i));
    }

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(
                    " new session — Enter, then type a URI ",
                    theme::title(),
                )),
        ),
        r,
    );
}

fn uri_live_message(kind: usize, uri: &str, uri2: &str) -> (bool, String) {
    let uri = uri.trim();
    let uri2 = uri2.trim();
    if uri.is_empty() {
        return (false, "type a URI…".into());
    }
    match kind {
        0..=2 => match parse_target(uri) {
            Ok(t) => (true, format!("ok · {}", t.display())),
            Err(e) => (false, e.to_string()),
        },
        3 => {
            let a = parse_target(uri);
            let b = if uri2.is_empty() {
                Err(crate::cli::TargetParseError::Empty)
            } else {
                parse_target(uri2)
            };
            match (a, b) {
                (Ok(bind), Ok(up)) => (true, format!("ok · {} → {}", bind.display(), up.display())),
                (Err(e), _) => (false, format!("bind: {e}")),
                (Ok(_), Err(_)) if uri2.is_empty() => (false, "Tab → enter upstream URI".into()),
                (Ok(_), Err(e)) => (false, format!("upstream: {e}")),
            }
        }
        4 => match parse_diag(uri) {
            Ok(d) => (
                true,
                format!("ok · {}", crate::session::DiagSession::title_for(&d)),
            ),
            Err(e) => (false, e.to_string()),
        },
        5 => {
            if uri.is_empty() {
                (false, "type interface name (e.g. eth0, any)".into())
            } else {
                (true, format!("ok · live capture on {uri}"))
            }
        }
        6 => {
            if uri.is_empty() {
                (false, "type path to .pcap / .pcapng".into())
            } else if std::path::Path::new(uri).exists() {
                (true, format!("ok · {}", uri))
            } else {
                (true, format!("ok · {uri} (will try on open)"))
            }
        }
        _ => (false, "unknown kind".into()),
    }
}

fn draw_new_session_uri(
    frame: &mut Frame,
    area: Rect,
    ws: &mut Workspace,
    kind: usize,
    hits: &mut HitMap,
) {
    let is_proxy = kind == 3;
    let h = if is_proxy { 14 } else { 11 };
    let r = centered(area, 72, h);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);

    let kind_label = Workspace::NEW_KINDS.get(kind).copied().unwrap_or("session");
    let hint = Workspace::uri_hint(kind);
    let uri_text = textarea_util::text_of(&ws.uri_input);
    let uri2_text = textarea_util::text_of(&ws.uri_input2);
    let (ok, msg) = uri_live_message(kind, &uri_text, &uri2_text);
    let msg_style = if ok {
        theme::success()
    } else {
        theme::danger()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(Span::styled(
            format!(" new URI — {kind_label} "),
            theme::title(),
        ));
    let inner = block.inner(r);
    frame.render_widget(block, r);

    let constraints: Vec<Constraint> = if is_proxy {
        vec![
            Constraint::Length(1), // hint
            Constraint::Length(1), // bind label
            Constraint::Length(3), // uri
            Constraint::Length(1), // up label
            Constraint::Length(3), // uri2
            Constraint::Length(1), // validation
            Constraint::Min(1),
        ]
    } else {
        vec![
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(1),
        ]
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    frame.render_widget(Paragraph::new(Span::styled(hint, theme::dim())), chunks[0]);

    if is_proxy {
        frame.render_widget(
            Paragraph::new(Span::styled(
                if ws.uri_field == 0 {
                    " Bind URI:"
                } else {
                    " Bind URI"
                },
                if ws.uri_field == 0 {
                    theme::accent()
                } else {
                    theme::label()
                },
            )),
            chunks[1],
        );
        style_uri_field(&mut ws.uri_input, ws.uri_field == 0);
        textarea_util::set_placeholder(&mut ws.uri_input, Workspace::uri_placeholder(kind));
        paint_textarea(frame, chunks[2], &mut ws.uri_input, ws.uri_field == 0, None);

        frame.render_widget(
            Paragraph::new(Span::styled(
                if ws.uri_field == 1 {
                    " Upstream URI:"
                } else {
                    " Upstream URI"
                },
                if ws.uri_field == 1 {
                    theme::accent()
                } else {
                    theme::label()
                },
            )),
            chunks[3],
        );
        style_uri_field(&mut ws.uri_input2, ws.uri_field == 1);
        textarea_util::set_placeholder(&mut ws.uri_input2, "tcp://127.0.0.1:9090");
        paint_textarea(
            frame,
            chunks[4],
            &mut ws.uri_input2,
            ws.uri_field == 1,
            None,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {msg}"), msg_style)),
            chunks[5],
        );
        let mitm = if ws.uri_tls_intercept {
            "TLS intercept: ON (Space/i toggle) · HTTP/1.1 ALPN only"
        } else {
            "TLS intercept: off (Space/i toggle)"
        };
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!(" Tab field · Enter open · Esc back · {mitm}"),
                theme::dim(),
            )),
            chunks[6],
        );
    } else {
        frame.render_widget(
            Paragraph::new(Span::styled(" URI:", theme::label())),
            chunks[1],
        );
        style_uri_field(&mut ws.uri_input, true);
        textarea_util::set_placeholder(&mut ws.uri_input, Workspace::uri_placeholder(kind));
        paint_textarea(frame, chunks[2], &mut ws.uri_input, true, None);
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {msg}"), msg_style)),
            chunks[3],
        );
        frame.render_widget(
            Paragraph::new(Span::styled(" Enter open · Esc back", theme::dim())),
            chunks[4],
        );
    }
}

fn style_uri_field(ta: &mut TextArea<'static>, focused: bool) {
    if focused {
        textarea_util::style_focused(ta);
    } else {
        textarea_util::style_unfocused(ta);
    }
}

fn draw_filter(frame: &mut Frame, area: Rect, ws: &mut Workspace, hits: &mut HitMap) {
    let r = Rect::new(
        area.x + 2,
        area.bottom().saturating_sub(5),
        area.width.saturating_sub(4),
        4,
    );
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    textarea_util::set_placeholder(&mut ws.filter_input, "text | hex:aabb | dir:in");
    paint_textarea(
        frame,
        r,
        &mut ws.filter_input,
        true,
        Some(Line::from(Span::styled(
            " filter (text | hex:aabb | dir:in) ",
            theme::title(),
        ))),
    );
}

fn draw_collections(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let r = centered(area, 60, 18);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let env = ws
        .collection
        .as_ref()
        .map(|c| format!("env:{}", c.active_env_name()))
        .unwrap_or_else(|| "env:—".into());
    let (title, items): (String, Vec<ListItem>) = if ws.collection_show_requests {
        let col = ws.collection.as_ref();
        let title = format!(
            " requests · {} · {env} · Enter load · s overwrite · S append · d delete · Esc ",
            col.map(|c| c.name.as_str()).unwrap_or("?")
        );
        let items = if let Some(c) = col {
            if c.requests.is_empty() {
                vec![ListItem::new(Span::styled(
                    "  (no requests — press s on HTTP to save)",
                    theme::dim(),
                ))]
            } else {
                c.requests
                    .iter()
                    .enumerate()
                    .map(|(i, req)| {
                        let style = if i == ws.request_cursor {
                            theme::selected(theme::accent())
                        } else {
                            theme::value()
                        };
                        let method = req.method.as_deref().unwrap_or("?");
                        let mut badges = String::new();
                        if req.kind == "grpc" || req.grpc_mode {
                            badges.push_str(" [grpc]");
                        }
                        if !req.tests.is_empty() {
                            badges.push_str(&format!(" [tests:{}]", req.tests.len()));
                        }
                        let label = format!("  {method:<6} {}{badges}", req.name);
                        let row_y = r.y.saturating_add(1).saturating_add(i as u16);
                        if row_y < r.y.saturating_add(r.height.saturating_sub(1)) {
                            hits.push(
                                Rect::new(r.x.saturating_add(1), row_y, r.width.saturating_sub(2), 1),
                                HitTarget::CollectionRow(i),
                            );
                        }
                        ListItem::new(Span::styled(label, style))
                    })
                    .collect()
            }
        } else {
            vec![ListItem::new(Span::styled("  (none)", theme::dim()))]
        };
        (title, items)
    } else {
        let title = format!(" collections · {env} · Enter open · s save ");
        let items = if ws.collection_names.is_empty() {
            vec![ListItem::new(Span::styled(
                "  (no collections yet — saved under ~/.config/bitbeak/)",
                theme::dim(),
            ))]
        } else {
            ws.collection_names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let style = if i == ws.collection_cursor {
                        theme::selected(theme::accent())
                    } else {
                        theme::value()
                    };
                    let row_y = r.y.saturating_add(1).saturating_add(i as u16);
                    if row_y < r.y.saturating_add(r.height.saturating_sub(1)) {
                        hits.push(
                            Rect::new(r.x.saturating_add(1), row_y, r.width.saturating_sub(2), 1),
                            HitTarget::CollectionRow(i),
                        );
                    }
                    ListItem::new(Span::styled(format!("  {n}"), style))
                })
                .collect()
        };
        (title, items)
    };
    frame.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(title, theme::title())),
        ),
        r,
    );
}

fn draw_edit_overlay(frame: &mut Frame, area: Rect, ws: &mut Workspace, hits: &mut HitMap) {
    let r = centered(area, 72, 16);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let title = match ws.overlay {
        Overlay::TestsEdit => " tests (one expr/line) · Ctrl+Enter save · Esc cancel ",
        Overlay::PreScriptEdit => " pre-script (Rhai) · Ctrl+Enter save · Esc cancel ",
        _ => " edit ",
    };
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::accent())
            .title(Span::styled(title, theme::title())),
        r,
    );
    let inner = Rect::new(
        r.x.saturating_add(1),
        r.y.saturating_add(1),
        r.width.saturating_sub(2),
        r.height.saturating_sub(2),
    );
    style_textarea(&mut ws.edit_ta, true, false, None);
    frame.render_widget(&ws.edit_ta, inner);
}

fn draw_bench(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let r = centered(area, 60, 10);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let text = if let Some(b) = &ws.bench_result {
        format!(
            "ok={} err={} bytes={} elapsed={}ms\np50={} p95={} p99={}\n{}",
            b.ok,
            b.err,
            b.bytes,
            b.elapsed_ms,
            b.p50,
            b.p95,
            b.p99,
            b.sparkline(40)
        )
    } else {
        "No bench result yet.\nOn HTTP session, F7 runs 10 sequential requests.".into()
    };
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" bench ", theme::title())),
        ),
        r,
    );
}

fn draw_fuzz(frame: &mut Frame, area: Rect, ws: &Workspace, hits: &mut HitMap) {
    let r = centered(area, 56, 12);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    let kinds: String = crate::fuzz::Mutator::all()
        .iter()
        .map(|m| m.label())
        .collect::<Vec<_>>()
        .join(", ");
    frame.render_widget(
        Paragraph::new(format!(
            "F11 / : fuzz — mutate composer payload once and send.\n\n\
Mutators: {kinds}\n\n\
Need an active Stream or Listen tab with composer text.\n\
Enter = send mutated copy · Esc = cancel\n\
Seed: {}",
            ws.fuzz_seed
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme::border())
                .title(Span::styled(" fuzz ", theme::title())),
        ),
        r,
    );
}

fn draw_palette(frame: &mut Frame, area: Rect, ws: &mut Workspace, hits: &mut HitMap) {
    let r = Rect::new(area.x + 4, area.y + 2, area.width.saturating_sub(8), 3);
    register_overlay_dismiss(area, r, hits);
    frame.render_widget(Clear, r);
    textarea_util::set_placeholder(
        &mut ws.palette_input,
        "sniff · follow-http · replay-http · help",
    );
    paint_textarea(
        frame,
        r,
        &mut ws.palette_input,
        true,
        Some(Line::from(Span::styled(
            " : sniff → follow-http → r · help · quit ",
            theme::title(),
        ))),
    );
}

/// Draw into a TestBackend for smoke tests.
pub fn draw_test(
    ws: &mut Workspace,
    width: u16,
    height: u16,
) -> ratatui::Terminal<ratatui::backend::TestBackend> {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
    terminal
        .draw(|f| {
            let _ = draw(f, ws);
        })
        .expect("draw");
    terminal
}

pub fn screen_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
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
