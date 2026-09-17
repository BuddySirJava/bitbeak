//! Saved collections and environments (XDG config).

pub mod import;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::http::{AuthKind, BodyMode, FormField, HttpVersion, RequestTest};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Environment {
    pub name: String,
    pub vars: Vec<(String, String)>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedRequest {
    pub name: String,
    pub kind: String, // "http" | "raw" | "graphql" | "grpc"
    pub target: String,
    pub method: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    #[serde(default)]
    pub auth: AuthKind,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub auth_user: String,
    #[serde(default)]
    pub auth_pass: String,
    #[serde(default)]
    pub auth_key: String,
    #[serde(default)]
    pub auth_value: String,
    #[serde(default)]
    pub body_mode: BodyMode,
    #[serde(default)]
    pub form_fields: Vec<FormField>,
    #[serde(default)]
    pub tests: Vec<RequestTest>,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u8,
    #[serde(default)]
    pub http_version: HttpVersion,
    #[serde(default)]
    pub graphql_variables: String,
    #[serde(default)]
    pub graphql_operation: String,
    #[serde(default)]
    pub pre_script: String,
    #[serde(default)]
    pub grpc_mode: bool,
    #[serde(default)]
    pub grpc_descriptor: String,
    #[serde(default)]
    pub grpc_message_type: String,
    #[serde(default)]
    pub grpc_reply_type: String,
}

fn default_max_redirects() -> u8 {
    10
}

impl Default for SavedRequest {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: "http".into(),
            target: String::new(),
            method: Some("GET".into()),
            headers: Vec::new(),
            body: String::new(),
            auth: AuthKind::None,
            auth_token: String::new(),
            auth_user: String::new(),
            auth_pass: String::new(),
            auth_key: "X-Api-Key".into(),
            auth_value: String::new(),
            body_mode: BodyMode::Raw,
            form_fields: Vec::new(),
            tests: Vec::new(),
            follow_redirects: true,
            max_redirects: 10,
            http_version: HttpVersion::Auto,
            graphql_variables: String::new(),
            graphql_operation: String::new(),
            pre_script: String::new(),
            grpc_mode: false,
            grpc_descriptor: String::new(),
            grpc_message_type: String::new(),
            grpc_reply_type: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Collection {
    pub name: String,
    pub requests: Vec<SavedRequest>,
    pub environments: Vec<Environment>,
    pub active_env: Option<String>,
}

impl Collection {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn substitute(&self, text: &str) -> String {
        let mut out = text.to_string();
        if let Some(env_name) = &self.active_env {
            if let Some(env) = self.environments.iter().find(|e| &e.name == env_name) {
                for (k, v) in &env.vars {
                    out = out.replace(&format!("{{{{{k}}}}}"), v);
                }
            }
        }
        out
    }

    pub fn active_env_name(&self) -> &str {
        self.active_env.as_deref().unwrap_or("(none)")
    }

    pub fn cycle_env(&mut self) {
        if self.environments.is_empty() {
            self.active_env = None;
            return;
        }
        let idx = self
            .active_env
            .as_ref()
            .and_then(|n| self.environments.iter().position(|e| &e.name == n))
            .map(|i| (i + 1) % self.environments.len())
            .unwrap_or(0);
        self.active_env = Some(self.environments[idx].name.clone());
    }

    pub fn set_env(&mut self, name: &str) -> bool {
        if self.environments.iter().any(|e| e.name == name) {
            self.active_env = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn find_request(&self, name: &str) -> Option<&SavedRequest> {
        self.requests
            .iter()
            .find(|r| r.name == name || r.name.ends_with(&format!("/{name}")))
    }
}

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bitbeak")
}

pub fn collections_dir() -> PathBuf {
    config_dir().join("collections")
}

pub fn ensure_dirs() -> Result<()> {
    fs::create_dir_all(collections_dir()).context("create collections dir")?;
    fs::create_dir_all(config_dir().join("ca")).context("create ca dir")?;
    Ok(())
}

pub fn collection_path(name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    collections_dir().join(format!("{safe}.toml"))
}

pub fn save_collection(col: &Collection) -> Result<PathBuf> {
    ensure_dirs()?;
    let path = collection_path(&col.name);
    let text = toml::to_string_pretty(col).context("serialize collection")?;
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

pub fn load_collection(name_or_path: &str) -> Result<Collection> {
    let path = if Path::new(name_or_path).exists() {
        PathBuf::from(name_or_path)
    } else {
        collection_path(name_or_path)
    };
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&text).context("parse collection toml")
}

pub fn list_collections() -> Result<Vec<String>> {
    ensure_dirs()?;
    let mut names = Vec::new();
    for entry in fs::read_dir(collections_dir())? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_substitute() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("demo.toml");
        let mut col = Collection::new("demo");
        col.environments.push(Environment {
            name: "local".into(),
            vars: vec![("baseUrl".into(), "http://127.0.0.1:9".into())],
        });
        col.active_env = Some("local".into());
        let text = toml::to_string_pretty(&col).unwrap();
        fs::write(&path, text).unwrap();
        let loaded: Collection = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.substitute("{{baseUrl}}/v1"), "http://127.0.0.1:9/v1");
    }

    #[test]
    fn cycle_env() {
        let mut col = Collection::new("x");
        col.environments.push(Environment {
            name: "a".into(),
            vars: vec![],
        });
        col.environments.push(Environment {
            name: "b".into(),
            vars: vec![],
        });
        col.cycle_env();
        assert_eq!(col.active_env.as_deref(), Some("a"));
        col.cycle_env();
        assert_eq!(col.active_env.as_deref(), Some("b"));
    }
}
