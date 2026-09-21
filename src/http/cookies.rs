//! Cookie jar with TOML persistence.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::collections::config_dir;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub same_site: String,
    /// Unix epoch seconds; `None` means session cookie.
    #[serde(default)]
    pub expires_at: Option<u64>,
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
        let is_https = url.starts_with("https://");
        let now = now_secs();
        let mut parts = Vec::new();
        for c in &self.cookies {
            if let Some(exp) = c.expires_at {
                if exp <= now {
                    continue;
                }
            }
            if c.secure && !is_https {
                continue;
            }
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
        let now = now_secs();
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            if let Some(c) = parse_set_cookie(v, &host, &default_path, now) {
                self.cookies
                    .retain(|x| !(x.name == c.name && x.domain == c.domain));
                if c.expires_at.is_some_and(|exp| exp <= now) {
                    continue;
                }
                self.cookies.push(c);
            }
        }
        self.cookies
            .retain(|c| c.expires_at.is_none_or(|exp| exp > now));
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let hostport = rest.split('/').next()?.split('?').next()?;
    if let Some(inner) = hostport.strip_prefix('[') {
        let host = inner.split(']').next()?;
        return Some(host.to_ascii_lowercase());
    }
    let host = hostport
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(hostport);
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

fn parse_set_cookie(raw: &str, default_host: &str, default_path: &str, now: u64) -> Option<Cookie> {
    let mut parts = raw.split(';');
    let nv = parts.next()?;
    let (name, value) = nv.split_once('=')?;
    let mut domain = default_host.to_string();
    let mut path = default_path.to_string();
    let mut secure = false;
    let mut http_only = false;
    let mut same_site = String::new();
    let mut expires_at = None;
    for attr in parts {
        let attr = attr.trim();
        if attr.eq_ignore_ascii_case("secure") {
            secure = true;
            continue;
        }
        if attr.eq_ignore_ascii_case("httponly") {
            http_only = true;
            continue;
        }
        if let Some((k, v)) = attr.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("domain") {
                domain = v.trim_start_matches('.').to_ascii_lowercase();
            } else if k.eq_ignore_ascii_case("path") {
                path = v.to_string();
            } else if k.eq_ignore_ascii_case("max-age") {
                if let Ok(secs) = v.parse::<i64>() {
                    if secs <= 0 {
                        expires_at = Some(now.saturating_sub(1));
                    } else {
                        expires_at = Some(now.saturating_add(secs as u64));
                    }
                }
            } else if k.eq_ignore_ascii_case("expires") {
                if let Some(ts) = parse_http_date(v) {
                    expires_at = Some(ts);
                }
            } else if k.eq_ignore_ascii_case("samesite") {
                same_site = v.to_string();
            }
        }
    }
    Some(Cookie {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
        domain,
        path,
        secure,
        http_only,
        same_site,
        expires_at,
    })
}

/// Minimal HTTP-date parser for `Expires=` (RFC 7231 IMF-fix).
fn parse_http_date(s: &str) -> Option<u64> {
    // Example: Wed, 21 Oct 2015 07:28:00 GMT
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1i32,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i32 = parts[3].parse().ok()?;
    let time = parts.get(4).copied().unwrap_or("00:00:00");
    let mut tp = time.split(':');
    let hour: u32 = tp.next()?.parse().ok()?;
    let min: u32 = tp.next()?.parse().ok()?;
    let sec: u32 = tp.next().unwrap_or("0").parse().ok()?;
    // Days from civil date (Howard Hinnant algorithm) → unix seconds.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe as i32 * 365 + (yoe / 4) as i32 - (yoe / 100) as i32 + doy;
    let days = (era as i64) * 146_097 + doe as i64 - 719_468;
    let secs = days * 86_400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    if secs < 0 {
        None
    } else {
        Some(secs as u64)
    }
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

    #[test]
    fn secure_cookie_not_sent_on_http() {
        let mut jar = CookieJar {
            enabled: true,
            cookies: Vec::new(),
        };
        jar.store_from_response(
            "https://api.example.com/",
            &[("Set-Cookie".into(), "tok=secret; Path=/; Secure".into())],
        );
        assert!(jar.cookies[0].secure);
        assert!(jar.cookie_header_for("https://api.example.com/").is_some());
        assert!(jar.cookie_header_for("http://api.example.com/").is_none());
    }

    #[test]
    fn max_age_zero_deletes_cookie() {
        let mut jar = CookieJar {
            enabled: true,
            cookies: vec![Cookie {
                name: "sid".into(),
                value: "abc".into(),
                domain: "example.com".into(),
                path: "/".into(),
                ..Default::default()
            }],
        };
        jar.store_from_response(
            "https://example.com/",
            &[("Set-Cookie".into(), "sid=x; Max-Age=0".into())],
        );
        assert!(jar.cookies.is_empty());
    }

    #[test]
    fn url_host_ipv4_and_ipv6() {
        assert_eq!(
            url_host("http://127.0.0.1:18081/v1"),
            Some("127.0.0.1".into())
        );
        assert_eq!(url_host("https://[::1]:8443/readyz"), Some("::1".into()));
        assert_eq!(
            url_host("https://api.example.com/v1"),
            Some("api.example.com".into())
        );
    }
}
