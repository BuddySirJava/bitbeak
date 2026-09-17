//! Cookie jar with TOML persistence.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::collections::config_dir;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CookieJar {
    pub enabled: bool,
    pub cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn path() -> PathBuf {
        config_dir().join("cookies.toml")
    }

    pub fn load() -> Self {
        let path = Self::path();
        if let Ok(text) = fs::read_to_string(&path) {
            toml::from_str(&text).unwrap_or_default()
        } else {
            Self {
                enabled: true,
                cookies: Vec::new(),
            }
        }
    }

    pub fn save(&self) -> Result<()> {
        crate::collections::ensure_dirs()?;
        let text = toml::to_string_pretty(self).context("serialize cookies")?;
        fs::write(Self::path(), text).context("write cookies")?;
        Ok(())
    }

    pub fn cookie_header_for(&self, url: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let host = url_host(url)?;
        let path = url_path(url);
        let mut parts = Vec::new();
        for c in &self.cookies {
            if domain_matches(&c.domain, &host) && path.starts_with(&c.path) {
                parts.push(format!("{}={}", c.name, c.value));
            }
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }

    pub fn store_from_response(&mut self, url: &str, headers: &[(String, String)]) {
        if !self.enabled {
            return;
        }
        let host = url_host(url).unwrap_or_default();
        let default_path = url_path(url);
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            if let Some(c) = parse_set_cookie(v, &host, &default_path) {
                self.cookies
                    .retain(|x| !(x.name == c.name && x.domain == c.domain));
                self.cookies.push(c);
            }
        }
    }
}

fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let hostport = rest.split('/').next()?;
    let host = hostport.split(':').next()?;
    Some(host.to_ascii_lowercase())
}

fn url_path(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    if let Some(i) = rest.find('/') {
        let p = &rest[i..];
        let p = p.split('?').next().unwrap_or(p);
        if p.is_empty() {
            "/".into()
        } else {
            p.to_string()
        }
    } else {
        "/".into()
    }
}

fn domain_matches(cookie_domain: &str, host: &str) -> bool {
    let d = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    host == d || host.ends_with(&format!(".{d}"))
}

fn parse_set_cookie(raw: &str, default_host: &str, default_path: &str) -> Option<Cookie> {
    let mut parts = raw.split(';');
    let nv = parts.next()?;
    let (name, value) = nv.split_once('=')?;
    let mut domain = default_host.to_string();
    let mut path = default_path.to_string();
    for attr in parts {
        let attr = attr.trim();
        if let Some((k, v)) = attr.split_once('=') {
            if k.eq_ignore_ascii_case("domain") {
                domain = v.trim().trim_start_matches('.').to_ascii_lowercase();
            } else if k.eq_ignore_ascii_case("path") {
                path = v.trim().to_string();
            }
        }
    }
    Some(Cookie {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
        domain,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_cookie() {
        let mut jar = CookieJar {
            enabled: true,
            cookies: Vec::new(),
        };
        jar.store_from_response(
            "https://api.example.com/v1",
            &[(
                "Set-Cookie".into(),
                "sid=abc; Path=/; Domain=example.com".into(),
            )],
        );
        assert_eq!(jar.cookies.len(), 1);
        let h = jar
            .cookie_header_for("https://api.example.com/v1/x")
            .unwrap();
        assert!(h.contains("sid=abc"));
    }
}
