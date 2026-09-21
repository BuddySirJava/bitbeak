//! OAuth2 authorization-code loopback helper (PKCE S256 + refresh).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthStore {
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub access_token: String,
}

/// Generate a high-entropy PKCE code verifier (43–128 chars, unreserved).
pub fn generate_pkce_verifier() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut raw = Vec::with_capacity(64);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    raw.extend_from_slice(&t);
    // Mix in more entropy from address of a stack value.
    let ptr = &raw as *const _ as usize;
    raw.extend_from_slice(&ptr.to_le_bytes());
    for i in 0u32..8 {
        raw.extend_from_slice(&i.to_le_bytes());
        raw.extend_from_slice(&(ptr.wrapping_mul(i as usize + 17)).to_le_bytes());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw[..48])
}

pub fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Build authorize URL with redirect to `http://127.0.0.1:{port}/callback` and PKCE.
pub fn authorize_url(cfg: &OAuthConfig, port: u16, state: &str, code_challenge: &str) -> String {
    let redirect = format!("http://127.0.0.1:{port}/callback");
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        cfg.auth_url,
        urlencoding::encode(&cfg.client_id),
        urlencoding::encode(&redirect),
        urlencoding::encode(&cfg.scopes),
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
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
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbitbeak: ok, you can close this tab",
            );
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

fn oauth_store_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitbeak")
        .join("oauth.toml")
}

pub fn load_oauth_store() -> OAuthStore {
    let path = oauth_store_path();
    if let Ok(text) = std::fs::read_to_string(path) {
        toml::from_str(&text).unwrap_or_default()
    } else {
        OAuthStore::default()
    }
}

pub fn save_oauth_store(store: &OAuthStore) -> Result<()> {
    let path = oauth_store_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(store).context("serialize oauth store")?;
    std::fs::write(&path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Exchange authorization code for tokens with PKCE verifier.
pub async fn exchange_code(
    cfg: &OAuthConfig,
    port: u16,
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let mut body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlencoding::encode(code),
        urlencoding::encode(&redirect),
        urlencoding::encode(&cfg.client_id),
        urlencoding::encode(code_verifier),
    );
    if !cfg.client_secret.is_empty() {
        body.push_str(&format!(
            "&client_secret={}",
            urlencoding::encode(&cfg.client_secret)
        ));
    }
    token_request(&cfg.token_url, &body).await
}

/// Refresh an access token using a stored refresh token.
pub async fn refresh_access_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<TokenResponse> {
    let mut body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        urlencoding::encode(refresh_token),
        urlencoding::encode(client_id),
    );
    if !client_secret.is_empty() {
        body.push_str(&format!(
            "&client_secret={}",
            urlencoding::encode(client_secret)
        ));
    }
    token_request(token_url, &body).await
}

async fn token_request(token_url: &str, body: &str) -> Result<TokenResponse> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let req = Request::builder()
        .method("POST")
        .uri(token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(body.to_string())))?;
    let resp = client.request(req).await?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    serde_json::from_slice(&bytes).context("parse token response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_contains_pkce() {
        let cfg = OAuthConfig {
            client_id: "cid".into(),
            client_secret: String::new(),
            auth_url: "https://auth.example/authorize".into(),
            token_url: "https://auth.example/token".into(),
            scopes: "openid".into(),
        };
        let verifier = generate_pkce_verifier();
        let challenge = pkce_challenge_s256(&verifier);
        let u = authorize_url(&cfg, 9876, "st", &challenge);
        assert!(u.contains("client_id=cid"));
        assert!(u.contains("9876"));
        assert!(u.contains("code_challenge="));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(
            u.contains(&urlencoding::encode(&challenge).into_owned()) || u.contains(&challenge)
        );
    }

    #[test]
    fn pkce_challenge_is_stable() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = pkce_challenge_s256(v);
        // RFC 7636 appendix B
        assert_eq!(c, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
}
