//! Import Postman Collection v2.1 and OpenAPI 3 into BitBeak collections.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;

use crate::collections::{Collection, SavedRequest};
use crate::http::RequestTest;

pub fn import_path(path: &Path) -> Result<Collection> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("imported")
        .to_string();
    if text.trim_start().starts_with('{') {
        if text.contains("\"openapi\"") || text.contains("\"swagger\"") {
            return import_openapi_json(&text, &name);
        }
        return import_postman_v21(&text);
    }
    if text.contains("openapi:") || text.contains("swagger:") {
        return import_openapi_yaml(&text, &name);
    }
    // Try Postman JSON anyway
    if let Ok(col) = import_postman_v21(&text) {
        return Ok(col);
    }
    import_openapi_yaml(&text, &name)
}

pub fn import_postman_v21(text: &str) -> Result<Collection> {
    let v: Json = serde_json::from_str(text).context("parse postman json")?;
    let info = v.get("info").context("missing info")?;
    let name = info
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("postman")
        .to_string();
    let mut col = Collection::new(name);
    if let Some(items) = v.get("item").and_then(|i| i.as_array()) {
        walk_postman_items(items, "", &mut col.requests);
    }
    Ok(col)
}

fn walk_postman_items(items: &[Json], folder: &str, out: &mut Vec<SavedRequest>) {
    for item in items {
        let name = item
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("request");
        if let Some(children) = item.get("item").and_then(|i| i.as_array()) {
            let next = if folder.is_empty() {
                name.to_string()
            } else {
                format!("{folder}/{name}")
            };
            walk_postman_items(children, &next, out);
            continue;
        }
        let Some(req) = item.get("request") else {
            continue;
        };
        let method = req
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("GET")
            .to_string();
        let url = postman_url(req.get("url"));
        let headers = postman_headers(req.get("header"));
        let body = postman_body(req.get("body"));
        let full_name = if folder.is_empty() {
            name.to_string()
        } else {
            format!("{folder}/{name}")
        };
        out.push(SavedRequest {
            name: full_name,
            kind: "http".into(),
            target: url,
            method: Some(method),
            headers,
            body,
            ..Default::default()
        });
    }
}

fn postman_url(v: Option<&Json>) -> String {
    let Some(v) = v else {
        return String::new();
    };
    if let Some(s) = v.as_str() {
        return s.to_string();
    }
    if let Some(raw) = v.get("raw").and_then(|r| r.as_str()) {
        return raw.to_string();
    }
    // host + path
    let host = v
        .get("host")
        .and_then(|h| h.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_default();
    let path = v
        .get("path")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default();
    let proto = v
        .get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("https");
    if host.is_empty() {
        path
    } else if path.is_empty() {
        format!("{proto}://{host}")
    } else {
        format!("{proto}://{host}/{path}")
    }
}

fn postman_headers(v: Option<&Json>) -> Vec<(String, String)> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|h| {
            let key = h.get("key")?.as_str()?;
            let val = h.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if h.get("disabled").and_then(|d| d.as_bool()) == Some(true) {
                return None;
            }
            Some((key.to_string(), val.to_string()))
        })
        .collect()
}

fn postman_body(v: Option<&Json>) -> String {
    let Some(v) = v else {
        return String::new();
    };
    if let Some(raw) = v.get("raw").and_then(|r| r.as_str()) {
        return raw.to_string();
    }
    String::new()
}

pub fn import_openapi_json(text: &str, fallback_name: &str) -> Result<Collection> {
    let v: Json = serde_json::from_str(text).context("parse openapi json")?;
    openapi_from_json(&v, fallback_name)
}

pub fn import_openapi_yaml(text: &str, fallback_name: &str) -> Result<Collection> {
    let y: Yaml = serde_yaml::from_str(text).context("parse openapi yaml")?;
    let json = yaml_to_json(y)?;
    openapi_from_json(&json, fallback_name)
}

fn yaml_to_json(y: Yaml) -> Result<Json> {
    serde_json::to_value(y).context("yaml to json")
}

fn openapi_from_json(v: &Json, fallback_name: &str) -> Result<Collection> {
    let name = v
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .unwrap_or(fallback_name)
        .to_string();
    let base = v
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("url"))
        .and_then(|u| u.as_str())
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();
    let paths = v
        .get("paths")
        .and_then(|p| p.as_object())
        .context("missing paths")?;
    let mut col = Collection::new(name);
    for (path, item) in paths {
        let Some(obj) = item.as_object() else {
            continue;
        };
        for (method, op) in obj {
            let m = method.to_ascii_uppercase();
            if !matches!(
                m.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                continue;
            }
            let op_id = op
                .get("operationId")
                .and_then(|o| o.as_str())
                .or_else(|| op.get("summary").and_then(|s| s.as_str()))
                .unwrap_or(path);
            let url = if base.is_empty() {
                path.clone()
            } else {
                format!("{base}{path}")
            };
            let body = example_body(op);
            let mut tests = Vec::new();
            if let Some(code) = first_success_code(op) {
                tests.push(RequestTest {
                    expr: format!("status == {code}"),
                });
            }
            col.requests.push(SavedRequest {
                name: format!("{m} {op_id}"),
                kind: "http".into(),
                target: url,
                method: Some(m),
                headers: vec![("Accept".into(), "application/json".into())],
                body,
                tests,
                ..Default::default()
            });
        }
    }
    if col.requests.is_empty() {
        bail!("no operations found in OpenAPI document");
    }
    Ok(col)
}

fn example_body(op: &Json) -> String {
    let body = op
        .get("requestBody")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.get("application/json"))
        .or_else(|| {
            op.get("requestBody")
                .and_then(|b| b.get("content"))
                .and_then(|c| c.as_object())
                .and_then(|m| m.values().next())
        });
    if let Some(ex) = body.and_then(|b| b.get("example")) {
        return serde_json::to_string_pretty(ex).unwrap_or_default();
    }
    if let Some(ex) = body
        .and_then(|b| b.get("examples"))
        .and_then(|e| e.as_object())
        .and_then(|m| m.values().next())
        .and_then(|e| e.get("value"))
    {
        return serde_json::to_string_pretty(ex).unwrap_or_default();
    }
    String::new()
}

fn first_success_code(op: &Json) -> Option<u16> {
    let resp = op.get("responses")?.as_object()?;
    for (k, _) in resp {
        if let Ok(code) = k.parse::<u16>() {
            if (200..300).contains(&code) {
                return Some(code);
            }
        }
    }
    if resp.contains_key("default") {
        return Some(200);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postman_flat() {
        let json = r#"{
          "info": {"name": "Demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item": [{
            "name": "Folder",
            "item": [{
              "name": "List",
              "request": {
                "method": "GET",
                "header": [{"key": "Accept", "value": "application/json"}],
                "url": "https://api.example.com/v1/items"
              }
            }]
          }]
        }"#;
        let col = import_postman_v21(json).unwrap();
        assert_eq!(col.name, "Demo");
        assert_eq!(col.requests.len(), 1);
        assert_eq!(col.requests[0].name, "Folder/List");
        assert_eq!(col.requests[0].target, "https://api.example.com/v1/items");
    }

    #[test]
    fn openapi_yaml() {
        let y = r#"
openapi: 3.0.0
info:
  title: Petstore
servers:
  - url: https://petstore.example.com
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
    post:
      operationId: createPet
      requestBody:
        content:
          application/json:
            example: {"name": "fluffy"}
      responses:
        "201":
          description: created
"#;
        let col = import_openapi_yaml(y, "x").unwrap();
        assert_eq!(col.name, "Petstore");
        assert_eq!(col.requests.len(), 2);
        let post = col
            .requests
            .iter()
            .find(|r| r.method.as_deref() == Some("POST"))
            .unwrap();
        assert!(post.body.contains("fluffy"));
        assert!(post.tests.iter().any(|t| t.expr.contains("201")));
    }
}
