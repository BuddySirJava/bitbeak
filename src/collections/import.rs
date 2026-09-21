//! Import Postman Collection v2.1 and OpenAPI 3 into BitBeak collections.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;

use crate::collections::{Collection, Environment, SavedRequest};
use crate::http::{AuthKind, BodyMode, FormField, RequestTest};

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
    if let Some(vars) = v.get("variable").and_then(|x| x.as_array()) {
        let mut env = Environment {
            name: "collection".into(),
            vars: Vec::new(),
        };
        for var in vars {
            let key = var
                .get("key")
                .and_then(|k| k.as_str())
                .unwrap_or_default()
                .to_string();
            if key.is_empty() {
                continue;
            }
            let val = var
                .get("value")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            env.vars.push((key, val));
        }
        if !env.vars.is_empty() {
            col.active_env = Some(env.name.clone());
            col.environments.push(env);
        }
    }
    let collection_auth = v.get("auth");
    if let Some(items) = v.get("item").and_then(|i| i.as_array()) {
        walk_postman_items(items, "", collection_auth, &mut col.requests);
    }
    Ok(col)
}

fn walk_postman_items(
    items: &[Json],
    folder: &str,
    inherited_auth: Option<&Json>,
    out: &mut Vec<SavedRequest>,
) {
    for item in items {
        let name = item
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("request");
        let auth = item.get("auth").or(inherited_auth);
        if let Some(children) = item.get("item").and_then(|i| i.as_array()) {
            let next = if folder.is_empty() {
                name.to_string()
            } else {
                format!("{folder}/{name}")
            };
            walk_postman_items(children, &next, auth, out);
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
        let (body_mode, body, form_fields) = postman_body_parts(req.get("body"));
        let full_name = if folder.is_empty() {
            name.to_string()
        } else {
            format!("{folder}/{name}")
        };
        let (auth_kind, auth_token, auth_user, auth_pass, auth_key, auth_value) =
            postman_auth(req.get("auth").or(auth));
        let pre_script = postman_prerequest(item.get("event").or_else(|| req.get("event")));
        let tests = postman_tests(item.get("event").or_else(|| req.get("event")));
        let kind = if body_mode == BodyMode::GraphQL {
            "graphql".into()
        } else {
            "http".into()
        };
        out.push(SavedRequest {
            name: full_name,
            kind,
            target: url,
            method: Some(method),
            headers,
            body,
            auth: auth_kind,
            auth_token,
            auth_user,
            auth_pass,
            auth_key,
            auth_value,
            body_mode,
            form_fields,
            pre_script,
            tests,
            ..Default::default()
        });
    }
}

fn postman_auth(auth: Option<&Json>) -> (AuthKind, String, String, String, String, String) {
    let Some(auth) = auth else {
        return (
            AuthKind::None,
            String::new(),
            String::new(),
            String::new(),
            "X-Api-Key".into(),
            String::new(),
        );
    };
    let typ = auth
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("noauth")
        .to_ascii_lowercase();
    let attrs = |name: &str| -> Vec<(String, String)> {
        auth.get(name)
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        Some((
                            x.get("key")?.as_str()?.to_string(),
                            x.get("value")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let find = |pairs: &[(String, String)], key: &str| -> String {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    match typ.as_str() {
        "bearer" => {
            let pairs = attrs("bearer");
            (
                AuthKind::Bearer,
                find(&pairs, "token"),
                String::new(),
                String::new(),
                "X-Api-Key".into(),
                String::new(),
            )
        }
        "basic" => {
            let pairs = attrs("basic");
            (
                AuthKind::Basic,
                String::new(),
                find(&pairs, "username"),
                find(&pairs, "password"),
                "X-Api-Key".into(),
                String::new(),
            )
        }
        "apikey" => {
            let pairs = attrs("apikey");
            let key = find(&pairs, "key");
            let value = find(&pairs, "value");
            let in_query = find(&pairs, "in").eq_ignore_ascii_case("query");
            (
                if in_query {
                    AuthKind::ApiKeyQuery
                } else {
                    AuthKind::ApiKeyHeader
                },
                String::new(),
                String::new(),
                String::new(),
                if key.is_empty() {
                    "X-Api-Key".into()
                } else {
                    key
                },
                value,
            )
        }
        _ => (
            AuthKind::None,
            String::new(),
            String::new(),
            String::new(),
            "X-Api-Key".into(),
            String::new(),
        ),
    }
}

fn postman_prerequest(event: Option<&Json>) -> String {
    let Some(arr) = event.and_then(|e| e.as_array()) else {
        return String::new();
    };
    for ev in arr {
        let listen = ev
            .get("listen")
            .and_then(|l| l.as_str())
            .unwrap_or_default();
        if listen != "prerequest" {
            continue;
        }
        let Some(script) = ev.get("script") else {
            continue;
        };
        if let Some(exec) = script.get("exec").and_then(|e| e.as_array()) {
            return exec
                .iter()
                .filter_map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join("\n");
        }
        if let Some(s) = script.get("exec").and_then(|e| e.as_str()) {
            return s.to_string();
        }
    }
    String::new()
}

/// Best-effort extraction of BitBeak assertion expressions from Postman test scripts.
fn postman_tests(event: Option<&Json>) -> Vec<RequestTest> {
    let Some(arr) = event.and_then(|e| e.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ev in arr {
        let listen = ev
            .get("listen")
            .and_then(|l| l.as_str())
            .unwrap_or_default();
        if listen != "test" {
            continue;
        }
        let Some(script) = ev.get("script") else {
            continue;
        };
        let text = if let Some(exec) = script.get("exec").and_then(|e| e.as_array()) {
            exec.iter()
                .filter_map(|l| l.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            script
                .get("exec")
                .and_then(|e| e.as_str())
                .unwrap_or("")
                .to_string()
        };
        // pm.response.to.have.status(200)
        for cap in text.split("to.have.status(").skip(1) {
            if let Some(num) = cap
                .split(')')
                .next()
                .and_then(|s| s.trim().parse::<u16>().ok())
            {
                out.push(RequestTest {
                    expr: format!("status == {num}"),
                });
            }
        }
        // pm.expect(pm.response.text()).to.include("ok")
        if text.contains(".to.include(") || text.contains(".to.contain(") {
            if let Some(start) = text.find(".to.include(\"").or_else(|| text.find(".to.contain(\""))
            {
                let rest = &text[start..];
                if let Some(q) = rest.find("(\"") {
                    let after = &rest[q + 2..];
                    if let Some(end) = after.find('"') {
                        out.push(RequestTest {
                            expr: format!("body contains {}", &after[..end]),
                        });
                    }
                }
            }
        }
    }
    out
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

fn postman_body_parts(v: Option<&Json>) -> (BodyMode, String, Vec<FormField>) {
    let Some(v) = v else {
        return (BodyMode::Raw, String::new(), Vec::new());
    };
    let mode = v
        .get("mode")
        .and_then(|m| m.as_str())
        .unwrap_or("raw")
        .to_ascii_lowercase();
    match mode.as_str() {
        "urlencoded" => {
            let fields = form_from_urlencoded(v.get("urlencoded"));
            (BodyMode::UrlEncoded, String::new(), fields)
        }
        "formdata" => {
            let fields = form_from_formdata(v.get("formdata"));
            (BodyMode::Multipart, String::new(), fields)
        }
        "graphql" => {
            let gql = v.get("graphql");
            let query = gql
                .and_then(|g| g.get("query"))
                .and_then(|q| q.as_str())
                .unwrap_or("")
                .to_string();
            (BodyMode::GraphQL, query, Vec::new())
        }
        _ => {
            let raw = v
                .get("raw")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string();
            (BodyMode::Raw, raw, Vec::new())
        }
    }
}

fn form_from_urlencoded(v: Option<&Json>) -> Vec<FormField> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|f| {
            if f.get("disabled").and_then(|d| d.as_bool()) == Some(true) {
                return None;
            }
            Some(FormField {
                key: f.get("key")?.as_str()?.to_string(),
                value: f
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                file: None,
            })
        })
        .collect()
}

fn form_from_formdata(v: Option<&Json>) -> Vec<FormField> {
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|f| {
            if f.get("disabled").and_then(|d| d.as_bool()) == Some(true) {
                return None;
            }
            let key = f.get("key")?.as_str()?.to_string();
            let typ = f
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("text")
                .to_ascii_lowercase();
            if typ == "file" {
                let path = f
                    .get("src")
                    .and_then(|s| {
                        s.as_str()
                            .map(|x| x.to_string())
                            .or_else(|| s.as_array()?.first()?.as_str().map(|x| x.to_string()))
                    })
                    .unwrap_or_default();
                Some(FormField {
                    key,
                    value: String::new(),
                    file: if path.is_empty() { None } else { Some(path) },
                })
            } else {
                Some(FormField {
                    key,
                    value: f
                        .get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    file: None,
                })
            }
        })
        .collect()
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
    let schemes = v
        .get("components")
        .and_then(|c| c.get("securitySchemes"))
        .cloned()
        .unwrap_or(Json::Object(Default::default()));
    let root_security = v.get("security");
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
            let mut url = if base.is_empty() {
                path.clone()
            } else {
                format!("{base}{path}")
            };
            url = append_query_params(&url, op);
            let body = example_body(op, v);
            let mut tests = Vec::new();
            if let Some(code) = first_success_code(op) {
                tests.push(RequestTest {
                    expr: format!("status == {code}"),
                });
            }
            let (auth, auth_token, auth_user, auth_pass, auth_key, auth_value) =
                openapi_auth(op.get("security").or(root_security), &schemes);
            col.requests.push(SavedRequest {
                name: format!("{m} {op_id}"),
                kind: "http".into(),
                target: url,
                method: Some(m),
                headers: vec![("Accept".into(), "application/json".into())],
                body,
                tests,
                auth,
                auth_token,
                auth_user,
                auth_pass,
                auth_key,
                auth_value,
                ..Default::default()
            });
        }
    }
    if col.requests.is_empty() {
        bail!("no operations found in OpenAPI document");
    }
    Ok(col)
}

fn append_query_params(url: &str, op: &Json) -> String {
    let Some(params) = op.get("parameters").and_then(|p| p.as_array()) else {
        return url.to_string();
    };
    let mut extras = Vec::new();
    for p in params {
        let loc = p
            .get("in")
            .and_then(|i| i.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if loc != "query" {
            continue;
        }
        let name = p.get("name").and_then(|n| n.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let example = p
            .get("example")
            .and_then(|e| e.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                p.get("schema")
                    .and_then(|s| s.get("example"))
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                p.get("schema")
                    .and_then(|s| s.get("default"))
                    .and_then(|e| e.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| format!("{{{{{name}}}}}"));
        extras.push(format!("{name}={example}"));
    }
    if extras.is_empty() {
        return url.to_string();
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{}", extras.join("&"))
}

fn openapi_auth(
    security: Option<&Json>,
    schemes: &Json,
) -> (AuthKind, String, String, String, String, String) {
    let none = (
        AuthKind::None,
        String::new(),
        String::new(),
        String::new(),
        "X-Api-Key".into(),
        String::new(),
    );
    let Some(arr) = security.and_then(|s| s.as_array()) else {
        return none;
    };
    let Some(first) = arr.first().and_then(|x| x.as_object()) else {
        return none;
    };
    let Some((scheme_name, _)) = first.iter().next() else {
        return none;
    };
    let Some(scheme) = schemes.get(scheme_name) else {
        return none;
    };
    let typ = scheme
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match typ.as_str() {
        "http" => {
            let scheme_name = scheme
                .get("scheme")
                .and_then(|s| s.as_str())
                .unwrap_or("bearer")
                .to_ascii_lowercase();
            if scheme_name == "basic" {
                (
                    AuthKind::Basic,
                    String::new(),
                    "{{username}}".into(),
                    "{{password}}".into(),
                    "X-Api-Key".into(),
                    String::new(),
                )
            } else {
                (
                    AuthKind::Bearer,
                    "{{token}}".into(),
                    String::new(),
                    String::new(),
                    "X-Api-Key".into(),
                    String::new(),
                )
            }
        }
        "apikey" => {
            let name = scheme
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("X-Api-Key")
                .to_string();
            let in_query = scheme
                .get("in")
                .and_then(|i| i.as_str())
                .unwrap_or("header")
                .eq_ignore_ascii_case("query");
            (
                if in_query {
                    AuthKind::ApiKeyQuery
                } else {
                    AuthKind::ApiKeyHeader
                },
                String::new(),
                String::new(),
                String::new(),
                name,
                "{{api_key}}".into(),
            )
        }
        _ => none,
    }
}

fn resolve_ref<'a>(doc: &'a Json, node: &'a Json) -> &'a Json {
    if let Some(r) = node.get("$ref").and_then(|r| r.as_str()) {
        if let Some(path) = r.strip_prefix("#/") {
            let mut cur = doc;
            for part in path.split('/') {
                match cur.get(part) {
                    Some(next) => cur = next,
                    None => return node,
                }
            }
            return cur;
        }
    }
    node
}

fn example_body(op: &Json, doc: &Json) -> String {
    let body = op
        .get("requestBody")
        .map(|b| resolve_ref(doc, b))
        .and_then(|b| b.get("content"))
        .and_then(|c| {
            c.get("application/json")
                .or_else(|| c.as_object()?.values().next())
        });
    let Some(media) = body else {
        return String::new();
    };
    let media = resolve_ref(doc, media);
    if let Some(ex) = media.get("example") {
        return serde_json::to_string_pretty(ex).unwrap_or_default();
    }
    if let Some(ex) = media
        .get("examples")
        .and_then(|e| e.as_object())
        .and_then(|m| m.values().next())
        .map(|e| resolve_ref(doc, e))
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
          "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
          "item": [{
            "name": "Folder",
            "item": [{
              "name": "List",
              "request": {
                "method": "GET",
                "header": [{"key": "Accept", "value": "application/json"}],
                "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "tok123"}]},
                "url": "{{baseUrl}}/v1/items",
                "body": {"mode": "urlencoded", "urlencoded": [{"key": "q", "value": "1"}]}
              }
            }]
          }]
        }"#;
        let col = import_postman_v21(json).unwrap();
        assert_eq!(col.name, "Demo");
        assert_eq!(col.requests.len(), 1);
        assert_eq!(col.requests[0].name, "Folder/List");
        assert_eq!(col.requests[0].target, "{{baseUrl}}/v1/items");
        assert_eq!(col.requests[0].auth, AuthKind::Bearer);
        assert_eq!(col.requests[0].auth_token, "tok123");
        assert_eq!(col.requests[0].body_mode, BodyMode::UrlEncoded);
        assert_eq!(col.requests[0].form_fields.len(), 1);
        assert_eq!(col.active_env.as_deref(), Some("collection"));
        assert_eq!(col.environments[0].vars[0].0, "baseUrl");
    }

    #[test]
    fn openapi_yaml() {
        let y = r#"
openapi: 3.0.0
info:
  title: Petstore
servers:
  - url: https://petstore.example.com
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
security:
  - bearerAuth: []
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - name: limit
          in: query
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
        let get = col
            .requests
            .iter()
            .find(|r| r.method.as_deref() == Some("GET"))
            .unwrap();
        assert!(get.target.contains("limit={{limit}}"));
        assert_eq!(get.auth, AuthKind::Bearer);
        let post = col
            .requests
            .iter()
            .find(|r| r.method.as_deref() == Some("POST"))
            .unwrap();
        assert!(post.body.contains("fluffy"));
        assert!(post.tests.iter().any(|t| t.expr.contains("201")));
    }
}
