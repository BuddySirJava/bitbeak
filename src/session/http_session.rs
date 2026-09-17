//! HTTP session state.

use bytes::Bytes;
use tui_textarea::TextArea;

use crate::cli::Target;
use crate::collections::{Collection, SavedRequest};
use crate::composer::ComposerMode;
use crate::frame::{Direction, FrameBuffer};
use crate::http::{
    append_history, build_graphql_body, format_headers, list_history, load_history_entry,
    parse_header_block, run_pre_script, run_tests, send_request, AssertResult, AuthKind, BodyMode,
    CookieJar, FormField, HistoryEntry, HttpRequestSpec, HttpResponse, HttpVersion, RequestTest,
};
use crate::inspect::InspectMode;
use crate::session::{ConnStatus, PaneFocus, SessionKind, SessionView};
use crate::transport::{CmdTx, IoEvent};
use crate::ui::textarea_util;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpField {
    Method,
    Url,
    AuthKind,
    AuthToken,
    AuthUser,
    AuthPass,
    AuthKey,
    AuthValue,
    Headers,
    Body,
    Form,
    GraphqlVars,
    GraphqlOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormCell {
    Key,
    Value,
    File,
}

pub struct HttpSession {
    pub target: Target,
    pub status: ConnStatus,
    pub frames: FrameBuffer,
    pub selected: usize,
    pub follow: bool,
    pub focus: PaneFocus,
    pub inspect: InspectMode,
    pub field: HttpField,
    pub method: TextArea<'static>,
    pub url: TextArea<'static>,
    pub headers: TextArea<'static>,
    pub body: TextArea<'static>,
    pub auth_token_ta: TextArea<'static>,
    pub auth_user_ta: TextArea<'static>,
    pub auth_pass_ta: TextArea<'static>,
    pub auth_key_ta: TextArea<'static>,
    pub auth_value_ta: TextArea<'static>,
    pub form_key_ta: TextArea<'static>,
    pub form_value_ta: TextArea<'static>,
    pub form_file_ta: TextArea<'static>,
    pub graphql_vars_ta: TextArea<'static>,
    pub graphql_op_ta: TextArea<'static>,
    pub composer_mode: ComposerMode,
    pub last_response: Option<HttpResponse>,
    pub history: Vec<String>,
    pub history_ids: Vec<String>,
    pub history_cursor: usize,
    pub history_scroll: usize,
    pub status_msg: String,
    pub filter: String,
    pub in_flight: bool,
    pub auth: AuthKind,
    pub body_mode: BodyMode,
    pub form_fields: Vec<FormField>,
    pub form_row: usize,
    pub form_cell: FormCell,
    pub tests: Vec<RequestTest>,
    pub last_assert: Vec<AssertResult>,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    pub cookies: CookieJar,
    pub http_version: HttpVersion,
    pub pre_script: String,
    pub grpc_mode: bool,
    pub grpc_descriptor_path: String,
    pub grpc_message_type: String,
    pub grpc_reply_type: String,
    pub oauth_scopes: String,
}

impl HttpSession {
    pub fn new(target: Target, max_frames: usize) -> Self {
        let url = target.display();
        let mut s = Self {
            target,
            status: ConnStatus::Idle,
            frames: FrameBuffer::new(max_frames),
            selected: 0,
            follow: true,
            focus: PaneFocus::Form,
            inspect: InspectMode::Raw,
            field: HttpField::Url,
            method: textarea_util::single_line("GET"),
            url: textarea_util::single_line(&url),
            headers: textarea_util::multi_line("User-Agent: bitbeak/0.1\nAccept: */*\n"),
            body: textarea_util::multi_line(""),
            auth_token_ta: textarea_util::single_line(""),
            auth_user_ta: textarea_util::single_line(""),
            auth_pass_ta: textarea_util::single_line(""),
            auth_key_ta: textarea_util::single_line("X-Api-Key"),
            auth_value_ta: textarea_util::single_line(""),
            form_key_ta: textarea_util::single_line(""),
            form_value_ta: textarea_util::single_line(""),
            form_file_ta: textarea_util::single_line(""),
            graphql_vars_ta: textarea_util::multi_line("{}"),
            graphql_op_ta: textarea_util::single_line(""),
            composer_mode: ComposerMode::Utf8,
            last_response: None,
            history: Vec::new(),
            history_ids: Vec::new(),
            history_cursor: 0,
            history_scroll: 0,
            status_msg: "Tab fields · Enter Send · History: focus + Enter replay".into(),
            filter: String::new(),
            in_flight: false,
            auth: AuthKind::None,
            body_mode: BodyMode::Raw,
            form_fields: Vec::new(),
            form_row: 0,
            form_cell: FormCell::Key,
            tests: Vec::new(),
            last_assert: Vec::new(),
            follow_redirects: true,
            max_redirects: 10,
            cookies: CookieJar::load(),
            http_version: HttpVersion::Auto,
            pre_script: String::new(),
            grpc_mode: false,
            grpc_descriptor_path: String::new(),
            grpc_message_type: String::new(),
            grpc_reply_type: String::new(),
            oauth_scopes: "openid".into(),
        };
        s.reload_history_pane();
        s.sync_field_styles();
        s
    }

    pub fn reload_history_pane(&mut self) {
        if let Ok(entries) = list_history(40) {
            self.history_ids = entries.iter().map(|e| e.id.clone()).collect();
            self.history = entries
                .into_iter()
                .map(|e| format!("{} {} → {} ({} ms)", e.method, e.url, e.status, e.total_ms))
                .collect();
            self.history_cursor = 0;
            self.history_scroll = 0;
        }
    }

    pub fn auth_token(&self) -> String {
        textarea_util::text_of(&self.auth_token_ta)
    }
    pub fn auth_user(&self) -> String {
        textarea_util::text_of(&self.auth_user_ta)
    }
    pub fn auth_pass(&self) -> String {
        textarea_util::text_of(&self.auth_pass_ta)
    }
    pub fn auth_key(&self) -> String {
        textarea_util::text_of(&self.auth_key_ta)
    }
    pub fn auth_value(&self) -> String {
        textarea_util::text_of(&self.auth_value_ta)
    }

    pub fn sync_form_editor_from_row(&mut self) {
        if let Some(f) = self.form_fields.get(self.form_row) {
            textarea_util::set_text(&mut self.form_key_ta, &f.key);
            textarea_util::set_text(&mut self.form_value_ta, &f.value);
            textarea_util::set_text(&mut self.form_file_ta, f.file.as_deref().unwrap_or(""));
        } else {
            textarea_util::set_text(&mut self.form_key_ta, "");
            textarea_util::set_text(&mut self.form_value_ta, "");
            textarea_util::set_text(&mut self.form_file_ta, "");
        }
    }

    pub fn commit_form_editor_to_row(&mut self) {
        if self.form_fields.is_empty() {
            return;
        }
        if self.form_row >= self.form_fields.len() {
            self.form_row = self.form_fields.len().saturating_sub(1);
        }
        let file = textarea_util::text_of(&self.form_file_ta);
        self.form_fields[self.form_row] = FormField {
            key: textarea_util::text_of(&self.form_key_ta),
            value: textarea_util::text_of(&self.form_value_ta),
            file: if file.is_empty() { None } else { Some(file) },
        };
    }

    pub fn form_add_row(&mut self) {
        self.commit_form_editor_to_row();
        self.form_fields.push(FormField {
            key: String::new(),
            value: String::new(),
            file: None,
        });
        self.form_row = self.form_fields.len() - 1;
        self.sync_form_editor_from_row();
        self.field = HttpField::Form;
    }

    pub fn form_delete_row(&mut self) {
        if self.form_fields.is_empty() {
            return;
        }
        self.form_fields.remove(self.form_row);
        if self.form_row > 0 && self.form_row >= self.form_fields.len() {
            self.form_row -= 1;
        }
        self.sync_form_editor_from_row();
    }

    pub fn cycle_field(&mut self) {
        self.commit_auth_and_form();
        self.field = match self.field {
            HttpField::Method => HttpField::Url,
            HttpField::Url => HttpField::AuthKind,
            HttpField::AuthKind => match self.auth {
                AuthKind::None => HttpField::Headers,
                AuthKind::Bearer => HttpField::AuthToken,
                AuthKind::Basic => HttpField::AuthUser,
                AuthKind::ApiKeyHeader | AuthKind::ApiKeyQuery => HttpField::AuthKey,
                AuthKind::OAuth2 => HttpField::AuthUser,
            },
            HttpField::AuthUser => HttpField::AuthPass,
            HttpField::AuthPass => match self.auth {
                AuthKind::OAuth2 => HttpField::AuthKey,
                _ => HttpField::Headers,
            },
            HttpField::AuthKey => HttpField::AuthValue,
            HttpField::AuthValue => match self.auth {
                AuthKind::OAuth2 => HttpField::AuthToken,
                _ => HttpField::Headers,
            },
            HttpField::AuthToken => HttpField::Headers,
            HttpField::Headers => match self.body_mode {
                BodyMode::Raw => HttpField::Body,
                BodyMode::GraphQL => HttpField::Body,
                BodyMode::UrlEncoded | BodyMode::Multipart => HttpField::Form,
            },
            HttpField::Body => {
                if matches!(self.body_mode, BodyMode::GraphQL) {
                    HttpField::GraphqlVars
                } else {
                    HttpField::Method
                }
            }
            HttpField::GraphqlVars => HttpField::GraphqlOp,
            HttpField::GraphqlOp | HttpField::Form => HttpField::Method,
        };
        if self.field == HttpField::Form {
            self.sync_form_editor_from_row();
        }
        self.sync_field_styles();
    }

    fn commit_auth_and_form(&mut self) {
        if matches!(
            self.field,
            HttpField::AuthToken
                | HttpField::AuthUser
                | HttpField::AuthPass
                | HttpField::AuthKey
                | HttpField::AuthValue
        ) {
            // textareas are source of truth
        }
        if self.field == HttpField::Form {
            self.commit_form_editor_to_row();
        }
    }

    pub fn cycle_auth(&mut self) {
        self.auth = match self.auth {
            AuthKind::None => AuthKind::Bearer,
            AuthKind::Bearer => AuthKind::Basic,
            AuthKind::Basic => AuthKind::ApiKeyHeader,
            AuthKind::ApiKeyHeader => AuthKind::ApiKeyQuery,
            AuthKind::ApiKeyQuery => AuthKind::OAuth2,
            AuthKind::OAuth2 => AuthKind::None,
        };
        self.field = HttpField::AuthKind;
        self.sync_field_styles();
    }

    pub fn cycle_body_mode(&mut self) {
        self.commit_form_editor_to_row();
        self.body_mode = match self.body_mode {
            BodyMode::Raw => BodyMode::UrlEncoded,
            BodyMode::UrlEncoded => BodyMode::Multipart,
            BodyMode::Multipart => BodyMode::GraphQL,
            BodyMode::GraphQL => BodyMode::Raw,
        };
        if matches!(self.body_mode, BodyMode::UrlEncoded | BodyMode::Multipart)
            && self.form_fields.is_empty()
        {
            self.form_add_row();
        }
        match self.body_mode {
            BodyMode::Raw | BodyMode::GraphQL => {
                self.field = HttpField::Body;
                if matches!(self.body_mode, BodyMode::GraphQL)
                    && textarea_util::text_of(&self.method).eq_ignore_ascii_case("GET")
                {
                    textarea_util::set_text(&mut self.method, "POST");
                }
            }
            BodyMode::UrlEncoded | BodyMode::Multipart => {
                self.field = HttpField::Form;
                self.sync_form_editor_from_row();
            }
        }
        self.sync_field_styles();
    }

    pub fn cycle_http_version(&mut self) {
        self.http_version = match self.http_version {
            HttpVersion::Auto => HttpVersion::Http1,
            HttpVersion::Http1 => HttpVersion::Http2,
            HttpVersion::Http2 => HttpVersion::Auto,
        };
    }

    pub fn set_field(&mut self, field: HttpField) {
        self.commit_auth_and_form();
        self.field = field;
        self.focus = PaneFocus::Form;
        if field == HttpField::Form {
            self.sync_form_editor_from_row();
        }
        self.sync_field_styles();
    }

    pub fn sync_field_styles(&mut self) {
        for ta in [
            &mut self.method,
            &mut self.url,
            &mut self.headers,
            &mut self.body,
            &mut self.auth_token_ta,
            &mut self.auth_user_ta,
            &mut self.auth_pass_ta,
            &mut self.auth_key_ta,
            &mut self.auth_value_ta,
            &mut self.form_key_ta,
            &mut self.form_value_ta,
            &mut self.form_file_ta,
            &mut self.graphql_vars_ta,
            &mut self.graphql_op_ta,
        ] {
            textarea_util::style_unfocused(ta);
        }
        if self.focus != PaneFocus::Form {
            return;
        }
        let focused: Option<&mut TextArea<'static>> = match self.field {
            HttpField::Method => Some(&mut self.method),
            HttpField::Url => Some(&mut self.url),
            HttpField::Headers => Some(&mut self.headers),
            HttpField::Body => Some(&mut self.body),
            HttpField::AuthToken => Some(&mut self.auth_token_ta),
            HttpField::AuthUser => Some(&mut self.auth_user_ta),
            HttpField::AuthPass => Some(&mut self.auth_pass_ta),
            HttpField::AuthKey => Some(&mut self.auth_key_ta),
            HttpField::AuthValue => Some(&mut self.auth_value_ta),
            HttpField::GraphqlVars => Some(&mut self.graphql_vars_ta),
            HttpField::GraphqlOp => Some(&mut self.graphql_op_ta),
            HttpField::Form => match self.form_cell {
                FormCell::Key => Some(&mut self.form_key_ta),
                FormCell::Value => Some(&mut self.form_value_ta),
                FormCell::File => Some(&mut self.form_file_ta),
            },
            HttpField::AuthKind => None,
        };
        if let Some(ta) = focused {
            textarea_util::style_focused(ta);
        }
    }

    pub fn active_textarea_mut(&mut self) -> Option<&mut TextArea<'static>> {
        if self.focus != PaneFocus::Form {
            return None;
        }
        match self.field {
            HttpField::Method => Some(&mut self.method),
            HttpField::Url => Some(&mut self.url),
            HttpField::Headers => Some(&mut self.headers),
            HttpField::Body => Some(&mut self.body),
            HttpField::AuthToken => Some(&mut self.auth_token_ta),
            HttpField::AuthUser => Some(&mut self.auth_user_ta),
            HttpField::AuthPass => Some(&mut self.auth_pass_ta),
            HttpField::AuthKey => Some(&mut self.auth_key_ta),
            HttpField::AuthValue => Some(&mut self.auth_value_ta),
            HttpField::GraphqlVars => Some(&mut self.graphql_vars_ta),
            HttpField::GraphqlOp => Some(&mut self.graphql_op_ta),
            HttpField::Form => match self.form_cell {
                FormCell::Key => Some(&mut self.form_key_ta),
                FormCell::Value => Some(&mut self.form_value_ta),
                FormCell::File => Some(&mut self.form_file_ta),
            },
            HttpField::AuthKind => None,
        }
    }

    pub fn load_history(&mut self, entry: &HistoryEntry) {
        textarea_util::set_text(&mut self.method, &entry.method);
        textarea_util::set_text(&mut self.url, &entry.url);
        textarea_util::set_text(&mut self.headers, &format_headers(&entry.request_headers));
        textarea_util::set_text(&mut self.body, &entry.request_body);
        self.body_mode = BodyMode::Raw;
        self.status_msg = format!("replay ready: {}", entry.id);
        self.focus = PaneFocus::Form;
        self.field = HttpField::Url;
        self.sync_field_styles();
    }

    pub fn replay_history_at_cursor(&mut self) {
        if let Some(id) = self.history_ids.get(self.history_cursor).cloned() {
            match load_history_entry(&id) {
                Ok(e) => self.load_history(&e),
                Err(err) => self.status_msg = format!("history: {err:#}"),
            }
        }
    }

    pub fn load_saved(&mut self, req: &SavedRequest) {
        textarea_util::set_text(&mut self.method, req.method.as_deref().unwrap_or("GET"));
        textarea_util::set_text(&mut self.url, &req.target);
        textarea_util::set_text(&mut self.headers, &format_headers(&req.headers));
        textarea_util::set_text(&mut self.body, &req.body);
        self.auth = req.auth;
        textarea_util::set_text(&mut self.auth_token_ta, &req.auth_token);
        textarea_util::set_text(&mut self.auth_user_ta, &req.auth_user);
        textarea_util::set_text(&mut self.auth_pass_ta, &req.auth_pass);
        textarea_util::set_text(
            &mut self.auth_key_ta,
            if req.auth_key.is_empty() {
                "X-Api-Key"
            } else {
                &req.auth_key
            },
        );
        textarea_util::set_text(&mut self.auth_value_ta, &req.auth_value);
        self.body_mode = req.body_mode;
        self.form_fields = req.form_fields.clone();
        self.form_row = 0;
        self.sync_form_editor_from_row();
        self.tests = req.tests.clone();
        self.follow_redirects = req.follow_redirects;
        self.max_redirects = req.max_redirects;
        self.http_version = req.http_version;
        textarea_util::set_text(&mut self.graphql_vars_ta, &req.graphql_variables);
        textarea_util::set_text(&mut self.graphql_op_ta, &req.graphql_operation);
        self.pre_script = req.pre_script.clone();
        self.grpc_mode = req.grpc_mode;
        self.grpc_descriptor_path = req.grpc_descriptor.clone();
        self.grpc_message_type = req.grpc_message_type.clone();
        self.grpc_reply_type = req.grpc_reply_type.clone();
        if req.kind == "graphql" {
            self.body_mode = BodyMode::GraphQL;
        }
        if req.kind == "grpc" {
            self.grpc_mode = true;
        }
        self.status_msg = format!("loaded {}", req.name);
        self.sync_field_styles();
    }

    pub fn to_saved(&self, name: impl Into<String>) -> SavedRequest {
        let mut form_fields = self.form_fields.clone();
        // ensure current editor row is included
        if matches!(self.body_mode, BodyMode::UrlEncoded | BodyMode::Multipart)
            && !form_fields.is_empty()
            && self.form_row < form_fields.len()
        {
            let file = textarea_util::text_of(&self.form_file_ta);
            form_fields[self.form_row] = FormField {
                key: textarea_util::text_of(&self.form_key_ta),
                value: textarea_util::text_of(&self.form_value_ta),
                file: if file.is_empty() { None } else { Some(file) },
            };
        }
        SavedRequest {
            name: name.into(),
            kind: if self.grpc_mode {
                "grpc".into()
            } else if matches!(self.body_mode, BodyMode::GraphQL) {
                "graphql".into()
            } else {
                "http".into()
            },
            target: textarea_util::text_of(&self.url),
            method: Some(textarea_util::text_of(&self.method)),
            headers: parse_header_block(&textarea_util::text_of(&self.headers)),
            body: textarea_util::text_of(&self.body),
            auth: self.auth,
            auth_token: self.auth_token(),
            auth_user: self.auth_user(),
            auth_pass: self.auth_pass(),
            auth_key: self.auth_key(),
            auth_value: self.auth_value(),
            body_mode: self.body_mode,
            form_fields,
            tests: self.tests.clone(),
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            http_version: self.http_version,
            graphql_variables: textarea_util::text_of(&self.graphql_vars_ta),
            graphql_operation: textarea_util::text_of(&self.graphql_op_ta),
            pre_script: self.pre_script.clone(),
            grpc_mode: self.grpc_mode,
            grpc_descriptor: self.grpc_descriptor_path.clone(),
            grpc_message_type: self.grpc_message_type.clone(),
            grpc_reply_type: self.grpc_reply_type.clone(),
        }
    }

    pub fn build_spec(&self, collection: Option<&Collection>) -> Result<HttpRequestSpec, String> {
        let body = crate::composer::decode_payload(
            &textarea_util::text_of(&self.body),
            self.composer_mode,
        )?;
        let mut form_fields = self.form_fields.clone();
        if matches!(self.body_mode, BodyMode::UrlEncoded | BodyMode::Multipart)
            && !form_fields.is_empty()
            && self.form_row < form_fields.len()
        {
            let file = textarea_util::text_of(&self.form_file_ta);
            form_fields[self.form_row] = FormField {
                key: textarea_util::text_of(&self.form_key_ta),
                value: textarea_util::text_of(&self.form_value_ta),
                file: if file.is_empty() { None } else { Some(file) },
            };
        }
        let mut spec = HttpRequestSpec {
            method: textarea_util::text_of(&self.method),
            url: textarea_util::text_of(&self.url),
            headers: parse_header_block(&textarea_util::text_of(&self.headers)),
            body: Bytes::from(body),
            follow_redirects: self.follow_redirects,
            max_redirects: self.max_redirects,
            auth: self.auth,
            auth_token: self.auth_token(),
            auth_user: self.auth_user(),
            auth_pass: self.auth_pass(),
            auth_key: self.auth_key(),
            auth_value: self.auth_value(),
            body_mode: self.body_mode,
            form_fields,
            http_version: self.http_version,
        };
        if matches!(self.body_mode, BodyMode::GraphQL) {
            let query = textarea_util::text_of(&self.body);
            let vars = textarea_util::text_of(&self.graphql_vars_ta);
            let op = textarea_util::text_of(&self.graphql_op_ta);
            let json = build_graphql_body(&query, &vars, &op)?;
            spec.body = Bytes::from(json);
            spec.body_mode = BodyMode::Raw;
            if !spec
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            {
                spec.headers
                    .push(("Content-Type".into(), "application/json".into()));
            }
            if spec.method.eq_ignore_ascii_case("GET") {
                spec.method = "POST".into();
            }
        }
        if let Some(col) = collection {
            spec.url = col.substitute(&spec.url);
            spec.auth_token = col.substitute(&spec.auth_token);
            spec.auth_user = col.substitute(&spec.auth_user);
            spec.auth_pass = col.substitute(&spec.auth_pass);
            spec.auth_value = col.substitute(&spec.auth_value);
            for (_, v) in &mut spec.headers {
                *v = col.substitute(v);
            }
            let body_s = String::from_utf8_lossy(&spec.body);
            let sub = col.substitute(&body_s);
            if sub.as_bytes() != spec.body.as_ref() {
                spec.body = Bytes::from(sub);
            }
            for f in &mut spec.form_fields {
                f.key = col.substitute(&f.key);
                f.value = col.substitute(&f.value);
            }
        }
        if matches!(spec.body_mode, BodyMode::UrlEncoded) && spec.form_fields.is_empty() {
            let text = String::from_utf8_lossy(&spec.body);
            for part in text.split(['&', '\n']) {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((k, v)) = part.split_once('=') {
                    spec.form_fields.push(FormField {
                        key: k.trim().to_string(),
                        value: v.trim().to_string(),
                        file: None,
                    });
                } else if let Some((k, v)) = part.split_once(':') {
                    spec.form_fields.push(FormField {
                        key: k.trim().to_string(),
                        value: v.trim().to_string(),
                        file: None,
                    });
                }
            }
        }
        if let Some(cookie) = self.cookies.cookie_header_for(&spec.url) {
            if let Some((_, v)) = spec
                .headers
                .iter_mut()
                .find(|(k, _)| k.eq_ignore_ascii_case("Cookie"))
            {
                *v = cookie;
            } else {
                spec.headers.push(("Cookie".into(), cookie));
            }
        }
        Ok(spec)
    }

    pub async fn send_now(&mut self, collection: Option<&Collection>) {
        if self.in_flight {
            return;
        }
        self.commit_form_editor_to_row();
        let mut spec = match self.build_spec(collection) {
            Ok(s) => s,
            Err(e) => {
                self.status_msg = e;
                return;
            }
        };
        let env: Vec<(String, String)> = collection
            .map(|c| {
                c.environments
                    .iter()
                    .find(|e| Some(&e.name) == c.active_env.as_ref())
                    .map(|e| e.vars.clone())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        if let Err(e) = run_pre_script(&self.pre_script, &mut spec, &env) {
            self.status_msg = e;
            return;
        }
        self.in_flight = true;
        self.status = ConnStatus::Connecting;
        self.status_msg = "sending…".into();

        if self.grpc_mode {
            let mut message = spec.body.clone();
            if !self.grpc_descriptor_path.is_empty() && !self.grpc_message_type.is_empty() {
                let json = String::from_utf8_lossy(&spec.body);
                match crate::http::grpc::json_to_protobuf(
                    std::path::Path::new(&self.grpc_descriptor_path),
                    &self.grpc_message_type,
                    &json,
                ) {
                    Ok(bytes) => message = bytes,
                    Err(e) => {
                        self.status = ConnStatus::Error;
                        self.status_msg = format!("grpc json→protobuf: {e:#}");
                        self.in_flight = false;
                        return;
                    }
                }
            }
            let grpc_req = crate::http::grpc::GrpcRequest {
                url: spec.url.clone(),
                message,
                authority: String::new(),
            };
            match crate::http::grpc::unary_call(&grpc_req).await {
                Ok(resp) => {
                    self.status = ConnStatus::Connected;
                    let body_preview = if !self.grpc_descriptor_path.is_empty()
                        && !self.grpc_message_type.is_empty()
                        && !resp.message.is_empty()
                    {
                        let reply_ty = crate::http::grpc::reply_message_type(
                            &self.grpc_message_type,
                            &self.grpc_reply_type,
                        );
                        match crate::http::grpc::protobuf_to_json(
                            std::path::Path::new(&self.grpc_descriptor_path),
                            &reply_ty,
                            &resp.message,
                        ) {
                            Ok(j) => format!("grpc-status={}\n{j}", resp.grpc_status),
                            Err(_) => format!(
                                "grpc-status={}\n{}",
                                resp.grpc_status,
                                String::from_utf8_lossy(&resp.message)
                            ),
                        }
                    } else if resp.message.is_empty() {
                        format!("grpc-status={} {}", resp.grpc_status, resp.grpc_message)
                    } else {
                        format!(
                            "grpc-status={}\n{}",
                            resp.grpc_status,
                            String::from_utf8_lossy(&resp.message)
                        )
                    };
                    self.frames.push_full(
                        Direction::Out,
                        Bytes::from(format!("gRPC {}", spec.url)),
                        None,
                        Some("grpc-request".into()),
                    );
                    self.frames.push_full(
                        Direction::In,
                        Bytes::from(body_preview.clone()),
                        None,
                        Some(format!("grpc {}", resp.grpc_status)),
                    );
                    self.status_msg = format!(
                        "grpc-status={} · {} B",
                        resp.grpc_status,
                        resp.message.len()
                    );
                    self.last_response = Some(HttpResponse {
                        status: resp.grpc_status as u16,
                        headers: resp.headers,
                        body: Bytes::from(body_preview),
                        timings: Default::default(),
                        tls: None,
                        redirect_chain: Vec::new(),
                        version: "h2".into(),
                    });
                }
                Err(e) => {
                    self.status = ConnStatus::Error;
                    self.status_msg = format!("{e:#}");
                }
            }
            self.in_flight = false;
            return;
        }

        match send_request(&spec).await {
            Ok(resp) => {
                self.status = ConnStatus::Connected;
                self.cookies.store_from_response(&spec.url, &resp.headers);
                let _ = self.cookies.save();
                let _ = append_history(&spec, &resp);
                self.reload_history_pane();
                self.last_assert = run_tests(&self.tests, &resp);
                let assert_summary = if self.last_assert.is_empty() {
                    String::new()
                } else {
                    let pass = self.last_assert.iter().filter(|a| a.passed).count();
                    let total = self.last_assert.len();
                    format!(" · tests {pass}/{total}")
                };
                let ver = &resp.version;
                self.frames.push_full(
                    Direction::Out,
                    Bytes::from(format!("{} {}", spec.method, spec.url)),
                    None,
                    Some("request".into()),
                );
                self.frames.push_full(
                    Direction::In,
                    resp.body.clone(),
                    None,
                    Some(format!("HTTP {} ({ver})", resp.status)),
                );
                self.status_msg = format!(
                    "{} · {} · {} ms · {} B{assert_summary}",
                    resp.status,
                    ver,
                    resp.timings.total_ms,
                    resp.body.len()
                );
                if self.follow {
                    let n = self.frames.len();
                    if n > 0 {
                        self.selected = n - 1;
                    }
                }
                self.last_response = Some(resp);
            }
            Err(e) => {
                self.status = ConnStatus::Error;
                self.status_msg = format!("{e:#}");
            }
        }
        self.in_flight = false;
    }

    pub fn auth_label(&self) -> String {
        match self.auth {
            AuthKind::None => "auth:none".into(),
            AuthKind::Bearer => format!(
                "auth:bearer {}",
                if self.auth_token().is_empty() {
                    "(empty)"
                } else {
                    "••••"
                }
            ),
            AuthKind::Basic => format!("auth:basic {}", self.auth_user()),
            AuthKind::ApiKeyHeader => format!("auth:header {}", self.auth_key()),
            AuthKind::ApiKeyQuery => format!("auth:query {}", self.auth_key()),
            AuthKind::OAuth2 => format!(
                "auth:oauth2 {}",
                if self.auth_token().is_empty() {
                    "(no token)"
                } else {
                    "••••"
                }
            ),
        }
    }

    pub fn field_hint(&self) -> &'static str {
        match self.field {
            HttpField::Method => "METHOD",
            HttpField::Url => "URL",
            HttpField::AuthKind => "AUTH",
            HttpField::AuthToken => "TOKEN",
            HttpField::AuthUser => "USER",
            HttpField::AuthPass => "PASS",
            HttpField::AuthKey => "KEY",
            HttpField::AuthValue => "VALUE",
            HttpField::Headers => "HEADERS",
            HttpField::Body => "BODY",
            HttpField::Form => "FORM",
            HttpField::GraphqlVars => "GQL-VARS",
            HttpField::GraphqlOp => "GQL-OP",
        }
    }

    pub fn response_summary_lines(&self) -> Vec<(String, ResponseLineKind)> {
        let Some(resp) = &self.last_response else {
            return vec![("(no response yet)".into(), ResponseLineKind::Normal)];
        };
        let mut lines = vec![
            (format!("status: {}", resp.status), ResponseLineKind::Normal),
            (
                format!(
                    "timings: dns {:?} tcp {:?} tls {:?} ttfb {:?} total {} ms",
                    resp.timings.dns_ms,
                    resp.timings.tcp_ms,
                    resp.timings.tls_ms,
                    resp.timings.ttfb_ms,
                    resp.timings.total_ms
                ),
                ResponseLineKind::Normal,
            ),
        ];
        if !self.last_assert.is_empty() {
            let pass = self.last_assert.iter().filter(|a| a.passed).count();
            lines.push((
                format!("── TESTS ({pass}/{}) ──", self.last_assert.len()),
                ResponseLineKind::Section,
            ));
            for a in &self.last_assert {
                lines.push((
                    format!(
                        "  {} {} ({})",
                        if a.passed { "PASS" } else { "FAIL" },
                        a.expr,
                        a.detail
                    ),
                    if a.passed {
                        ResponseLineKind::Pass
                    } else {
                        ResponseLineKind::Fail
                    },
                ));
            }
        }
        if !resp.redirect_chain.is_empty() {
            lines.push((
                format!("── REDIRECTS ({}) ──", resp.redirect_chain.len()),
                ResponseLineKind::Section,
            ));
            for h in &resp.redirect_chain {
                lines.push((
                    format!("  {} → {}", h.status, h.location),
                    ResponseLineKind::Redirect,
                ));
            }
        }
        lines.push((String::new(), ResponseLineKind::Normal));
        lines.push(("── headers ──".into(), ResponseLineKind::Section));
        for line in format_headers(&resp.headers).lines() {
            lines.push((line.to_string(), ResponseLineKind::Normal));
        }
        if let Some(tls) = &resp.tls {
            lines.push((String::new(), ResponseLineKind::Normal));
            lines.push(("── tls ──".into(), ResponseLineKind::Section));
            for l in crate::tlsinfo::format_tls_info(tls) {
                lines.push((l, ResponseLineKind::Normal));
            }
        }
        lines
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseLineKind {
    Normal,
    Section,
    Pass,
    Fail,
    Redirect,
}

impl SessionView for HttpSession {
    fn kind(&self) -> SessionKind {
        SessionKind::Http
    }

    fn title(&self) -> String {
        format!("HTTP {}", textarea_util::text_of(&self.url))
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn target_display(&self) -> String {
        textarea_util::text_of(&self.url)
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
        self.sync_field_styles();
    }

    fn on_io(&mut self, _event: IoEvent) {}

    fn cmd_tx(&self) -> Option<&CmdTx> {
        None
    }

    fn status_message(&self) -> &str {
        &self.status_msg
    }
}
