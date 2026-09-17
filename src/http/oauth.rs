//! OAuth2 authorization-code loopback helper.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub scopes: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub token_type: String,
}

/// Build authorize URL with redirect to `http://127.0.0.1:{port}/callback`.
pub fn authorize_url(cfg: &OAuthConfig, port: u16, state: &str) -> String {
    let redirect = format!("http://127.0.0.1:{port}/callback");
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        cfg.auth_url,
        urlencoding::encode(&cfg.client_id),
        urlencoding::encode(&redirect),
        urlencoding::encode(&cfg.scopes),
        urlencoding::encode(state)
    )
}

/// Listen once for `?code=`; returns the code. Times out after `timeout`.
pub fn wait_for_code(port: u16, timeout: Duration) -> Result<String> {
    let listener = TcpListener::bind(("127.0.0.1", port)).context("bind oauth callback")?;
    listener.set_nonblocking(false)?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let code = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|path| {
                    path.split('?').nth(1)?.split('&').find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        if k == "code" {
                            Some(v.to_string())
                        } else {
                            None
                        }
                    })
                });
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbitbeak: ok, you can close this tab");
            let _ = tx.send(code);
        }
    });
    match rx.recv_timeout(timeout) {
        Ok(Some(code)) => Ok(code),
        Ok(None) => bail!("oauth callback missing code"),
        Err(_) => bail!("oauth callback timed out"),
    }
}

pub fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()?;
    }
    Ok(())
}

/// Exchange authorization code for tokens (blocking HTTP via std — uses hyper async in callers preferably).
pub async fn exchange_code(cfg: &OAuthConfig, port: u16, code: &str) -> Result<TokenResponse> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let redirect = format!("http://127.0.0.1:{port}/callback");
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
        urlencoding::encode(code),
        urlencoding::encode(&redirect),
        urlencoding::encode(&cfg.client_id),
        urlencoding::encode(&cfg.client_secret),
    );
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let req = Request::builder()
        .method("POST")
        .uri(&cfg.token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(body)))?;
    let resp = client.request(req).await?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    serde_json::from_slice(&bytes).context("parse token response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_contains_client() {
        let cfg = OAuthConfig {
            client_id: "cid".into(),
            client_secret: String::new(),
            auth_url: "https://auth.example/authorize".into(),
            token_url: "https://auth.example/token".into(),
            scopes: "openid".into(),
        };
        let u = authorize_url(&cfg, 9876, "st");
        assert!(u.contains("client_id=cid"));
        assert!(u.contains("9876"));
    }
}
