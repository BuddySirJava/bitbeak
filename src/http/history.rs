//! Persistent HTTP request history.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::collections::config_dir;
use crate::http::{HttpRequestSpec, HttpResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub at_unix: u64,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub total_ms: u64,
    pub body_preview: String,
    pub request_headers: Vec<(String, String)>,
    pub request_body: String,
}

pub fn history_dir() -> PathBuf {
    config_dir().join("history")
}

pub fn append_history(spec: &HttpRequestSpec, resp: &HttpResponse) -> Result<PathBuf> {
    fs::create_dir_all(history_dir())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let id = format!("{ts}-{}", resp.status);
    let preview = String::from_utf8_lossy(&resp.body[..resp.body.len().min(512)]).into_owned();
    let entry = HistoryEntry {
        id: id.clone(),
        at_unix: ts,
        method: spec.method.clone(),
        url: spec.url.clone(),
        status: resp.status,
        total_ms: resp.timings.total_ms,
        body_preview: preview,
        request_headers: spec.headers.clone(),
        request_body: String::from_utf8_lossy(&spec.body).into_owned(),
    };
    let path = history_dir().join(format!("{id}.json"));
    let text = serde_json::to_string_pretty(&entry).context("serialize history")?;
    fs::write(&path, text)?;
    // Keep last 200
    prune(200)?;
    Ok(path)
}

fn prune(keep: usize) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(history_dir())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    entries.sort();
    if entries.len() > keep {
        for p in entries.iter().take(entries.len() - keep) {
            let _ = fs::remove_file(p);
        }
    }
    Ok(())
}

pub fn list_history(limit: usize) -> Result<Vec<HistoryEntry>> {
    let mut entries: Vec<HistoryEntry> = fs::read_dir(history_dir())
        .unwrap_or_else(|_| fs::read_dir(".").unwrap())
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            let text = fs::read_to_string(&p).ok()?;
            serde_json::from_str::<HistoryEntry>(&text).ok()
        })
        .collect();
    entries.sort_by_key(|a| std::cmp::Reverse(a.at_unix));
    entries.truncate(limit);
    Ok(entries)
}

pub fn load_history_entry(id: &str) -> Result<HistoryEntry> {
    let path = history_dir().join(format!("{id}.json"));
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}
