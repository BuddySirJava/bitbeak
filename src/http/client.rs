//! HTTP/HTTPS client with timing waterfall, auth, forms, redirects.

use std::time::Instant;

use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct HttpTimings {
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub total_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RedirectHop {
    pub status: u16,
    pub location: String,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub timings: HttpTimings,
    pub tls: Option<crate::tlsinfo::TlsInfo>,
    pub redirect_chain: Vec<RedirectHop>,
    /// Negotiated HTTP version label (e.g. "HTTP/1.1", "HTTP/2").
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    #[default]
    None,
    Bearer,
    Basic,
    ApiKeyHeader,
    ApiKeyQuery,
    OAuth2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    #[default]
    Auto,
    Http1,
    Http2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyMode {
    #[default]
    Raw,
    UrlEncoded,
    Multipart,
    GraphQL,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub key: String,
    pub value: String,
    /// If set, treat as file path for multipart.
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpRequestSpec {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    pub auth: AuthKind,
    pub auth_token: String,
    pub auth_user: String,
    pub auth_pass: String,
    pub auth_key: String,
    pub auth_value: String,
    pub body_mode: BodyMode,
    pub form_fields: Vec<FormField>,
    pub http_version: HttpVersion,
}

impl Default for HttpRequestSpec {
    fn default() -> Self {
        Self {
            method: "GET".into(),
            url: "https://example.com/".into(),
            headers: vec![("User-Agent".into(), "bitbeak/0.1".into())],
            body: Bytes::new(),
            follow_redirects: true,
            max_redirects: 10,
            auth: AuthKind::None,
            auth_token: String::new(),
            auth_user: String::new(),
            auth_pass: String::new(),
            auth_key: "X-Api-Key".into(),
            auth_value: String::new(),
            body_mode: BodyMode::Raw,
            form_fields: Vec::new(),
            http_version: HttpVersion::Auto,
        }
    }
}

pub fn apply_auth(spec: &mut HttpRequestSpec) {
    match spec.auth {
        AuthKind::None => {}
        AuthKind::Bearer => {
            if !spec.auth_token.is_empty() {
                upsert_header(
                    &mut spec.headers,
                    "Authorization",
                    &format!("Bearer {}", spec.auth_token),
                );
            }
        }
        AuthKind::Basic => {
            let raw = format!("{}:{}", spec.auth_user, spec.auth_pass);
            let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            upsert_header(&mut spec.headers, "Authorization", &format!("Basic {b64}"));
        }
        AuthKind::ApiKeyHeader => {
            if !spec.auth_key.is_empty() {
                upsert_header(&mut spec.headers, &spec.auth_key, &spec.auth_value);
            }
        }
        AuthKind::ApiKeyQuery => {
            if !spec.auth_key.is_empty() {
                let sep = if spec.url.contains('?') { '&' } else { '?' };
                spec.url = format!(
                    "{}{}{}={}",
                    spec.url,
                    sep,
                    urlencoding::encode(&spec.auth_key),
                    urlencoding::encode(&spec.auth_value)
                );
            }
        }
        AuthKind::OAuth2 => {
            // Token expected in auth_token after OAuth flow.
            if !spec.auth_token.is_empty() {
                upsert_header(
                    &mut spec.headers,
                    "Authorization",
                    &format!("Bearer {}", spec.auth_token),
                );
            }
        }
    }
}

fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, v)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        *v = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

pub fn build_form_body(mode: BodyMode, fields: &[FormField]) -> Result<(Bytes, Option<String>)> {
    match mode {
        BodyMode::Raw | BodyMode::GraphQL => Ok((Bytes::new(), None)),
        BodyMode::UrlEncoded => {
            let enc = fields
                .iter()
                .map(|f| {
                    format!(
                        "{}={}",
                        urlencoding::encode(&f.key),
                        urlencoding::encode(&f.value)
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            Ok((
                Bytes::from(enc),
                Some("application/x-www-form-urlencoded".into()),
            ))
        }
        BodyMode::Multipart => {
            let boundary = format!("----bitbeak{}", chrono_like_id());
            let mut body = Vec::new();
            for f in fields {
                body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                if let Some(path) = &f.file {
                    let data = std::fs::read(path)
                        .with_context(|| format!("read multipart file {path}"))?;
                    let fname = std::path::Path::new(path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file");
                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"; filename=\"{fname}\"\r\n\
                             Content-Type: application/octet-stream\r\n\r\n",
                            f.key
                        )
                        .as_bytes(),
                    );
                    body.extend_from_slice(&data);
                    body.extend_from_slice(b"\r\n");
                } else {
                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                            f.key, f.value
                        )
                        .as_bytes(),
                    );
                }
            }
            body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            Ok((
                Bytes::from(body),
                Some(format!("multipart/form-data; boundary={boundary}")),
            ))
        }
    }
}

fn chrono_like_id() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn send_request(spec: &HttpRequestSpec) -> Result<HttpResponse> {
    let mut spec = spec.clone();
    apply_auth(&mut spec);

    if matches!(spec.body_mode, BodyMode::UrlEncoded | BodyMode::Multipart)
        && !spec.form_fields.is_empty()
    {
        let (body, ctype) = build_form_body(spec.body_mode, &spec.form_fields)?;
        spec.body = body;
        if let Some(ct) = ctype {
            upsert_header(&mut spec.headers, "Content-Type", &ct);
        }
    }

    let start = Instant::now();
    let mut redirect_chain = Vec::new();
    let mut current_url = spec.url.clone();
    let mut current_method = spec.method.clone();
    let mut current_body = spec.body.clone();
    let mut hops = 0u8;

    let https = {
        let b = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http();
        match spec.http_version {
            HttpVersion::Http1 => b.enable_http1().build(),
            HttpVersion::Http2 => b.enable_http2().build(),
            HttpVersion::Auto => b.enable_http1().enable_http2().build(),
        }
    };
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let mut timings = HttpTimings::default();
    let mut tls_info = None;
    let mut last_headers = Vec::new();
    #[allow(unused_assignments)]
    let mut last_status = 0u16;
    #[allow(unused_assignments)]
    let mut last_body = Bytes::new();
    #[allow(unused_assignments)]
    let mut last_version = String::from("HTTP/1.1");

    loop {
        let uri: Uri = current_url.parse().context("parse url")?;
        let host = uri.host().unwrap_or("").to_string();
        let is_https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

        if hops == 0 {
            let dns_start = Instant::now();
            let _ = tokio::net::lookup_host(format!("{host}:{port}")).await;
            timings.dns_ms = Some(dns_start.elapsed().as_millis() as u64);
            if is_https {
                let tls_start = Instant::now();
                if let Ok(info) = crate::tlsinfo::probe_tls(&host, port).await {
                    timings.tls_ms = Some(info.handshake_ms);
                    tls_info = Some(info);
                } else {
                    timings.tls_ms = Some(tls_start.elapsed().as_millis() as u64);
                }
            }
        }

        let method: Method = current_method.parse().unwrap_or(Method::GET);
        let mut builder = Request::builder().method(method).uri(&uri);
        {
            let headers = builder.headers_mut().expect("headers");
            for (k, v) in &spec.headers {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }
        }
        let req = builder
            .body(Full::new(current_body.clone()))
            .context("build request")?;

        let ttfb_start = Instant::now();
        let resp = client.request(req).await.context("http request")?;
        if hops == 0 {
            timings.ttfb_ms = Some(ttfb_start.elapsed().as_millis() as u64);
        }

        last_status = resp.status().as_u16();
        let negotiated = match resp.version() {
            hyper::Version::HTTP_11 => "HTTP/1.1",
            hyper::Version::HTTP_2 => "HTTP/2",
            hyper::Version::HTTP_3 => "HTTP/3",
            hyper::Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP",
        }
        .to_string();
        last_headers.clear();
        for (k, v) in resp.headers().iter() {
            last_headers.push((
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            ));
        }
        last_body = resp
            .into_body()
            .collect()
            .await
            .context("read body")?
            .to_bytes();

        let is_redirect = matches!(last_status, 301 | 302 | 303 | 307 | 308);
        if !(spec.follow_redirects && is_redirect && hops < spec.max_redirects) {
            last_version = negotiated;
            break;
        }
        let loc = last_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone());
        let Some(loc) = loc else {
            last_version = negotiated;
            break;
        };
        redirect_chain.push(RedirectHop {
            status: last_status,
            location: loc.clone(),
        });
        current_url = resolve_location(&current_url, &loc);
        if last_status == 303 {
            current_method = "GET".into();
            current_body = Bytes::new();
        }
        hops += 1;
        let _ = negotiated;
    }

    timings.total_ms = start.elapsed().as_millis() as u64;
    if timings.tcp_ms.is_none() {
        let approx = timings
            .total_ms
            .saturating_sub(timings.dns_ms.unwrap_or(0))
            .saturating_sub(timings.tls_ms.unwrap_or(0))
            .saturating_sub(timings.ttfb_ms.unwrap_or(0) / 2);
        timings.tcp_ms = Some(approx.min(timings.total_ms));
    }

    Ok(HttpResponse {
        status: last_status,
        headers: last_headers,
        body: last_body,
        timings,
        tls: tls_info,
        redirect_chain,
        version: last_version,
    })
}

fn resolve_location(base: &str, loc: &str) -> String {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    if let Ok(base_uri) = base.parse::<Uri>() {
        let scheme = base_uri.scheme_str().unwrap_or("https");
        let auth = base_uri.authority().map(|a| a.as_str()).unwrap_or("");
        if loc.starts_with('/') {
            return format!("{scheme}://{auth}{loc}");
        }
        return format!("{scheme}://{auth}/{loc}");
    }
    loc.to_string()
}

/// Parse header lines "Name: value" into pairs.
pub fn parse_header_block(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

pub fn format_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_headers() {
        let h = parse_header_block("Accept: application/json\nX-Test: 1");
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0, "Accept");
    }

    #[test]
    fn bearer_auth() {
        let mut s = HttpRequestSpec {
            auth: AuthKind::Bearer,
            auth_token: "tok".into(),
            ..Default::default()
        };
        apply_auth(&mut s);
        assert!(s
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer tok"));
    }

    #[test]
    fn urlencoded_body() {
        let (b, ct) = build_form_body(
            BodyMode::UrlEncoded,
            &[FormField {
                key: "a".into(),
                value: "b c".into(),
                file: None,
            }],
        )
        .unwrap();
        assert_eq!(ct.unwrap(), "application/x-www-form-urlencoded");
        assert_eq!(&b[..], b"a=b%20c");
    }
}
