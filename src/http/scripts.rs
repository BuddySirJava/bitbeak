//! Rhai pre-request scripts.

use rhai::{Engine, Map, Scope};

use crate::http::HttpRequestSpec;

pub fn run_pre_script(
    script: &str,
    spec: &mut HttpRequestSpec,
    env: &[(String, String)],
) -> Result<(), String> {
    if script.trim().is_empty() {
        return Ok(());
    }
    let engine = Engine::new();
    let mut scope = Scope::new();
    let mut req = Map::new();
    req.insert("url".into(), spec.url.clone().into());
    req.insert("method".into(), spec.method.clone().into());
    req.insert(
        "body".into(),
        String::from_utf8_lossy(&spec.body).into_owned().into(),
    );
    let mut headers = Map::new();
    for (k, v) in &spec.headers {
        headers.insert(k.clone().into(), v.clone().into());
    }
    req.insert("headers".into(), headers.into());
    scope.push("req", req);
    let mut env_map = Map::new();
    for (k, v) in env {
        env_map.insert(k.clone().into(), v.clone().into());
    }
    scope.push("env", env_map);

    engine
        .run_with_scope(&mut scope, script)
        .map_err(|e| format!("pre-script: {e}"))?;

    if let Some(req) = scope.get_value::<Map>("req") {
        if let Some(v) = req.get("url") {
            if let Ok(s) = v.clone().into_string() {
                spec.url = s;
            }
        }
        if let Some(v) = req.get("method") {
            if let Ok(s) = v.clone().into_string() {
                spec.method = s;
            }
        }
        if let Some(v) = req.get("body") {
            if let Ok(s) = v.clone().into_string() {
                spec.body = bytes::Bytes::from(s);
            }
        }
        if let Some(v) = req.get("headers") {
            if let Some(map) = v.clone().try_cast::<Map>() {
                let mut out = Vec::new();
                for (k, val) in map.iter() {
                    let key = k.to_string();
                    if let Ok(s) = val.clone().into_string() {
                        out.push((key, s));
                    }
                }
                spec.headers = out;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutates_url() {
        let mut spec = HttpRequestSpec {
            url: "https://example.com/".into(),
            ..Default::default()
        };
        run_pre_script(r#"req.url = req.url + "v1";"#, &mut spec, &[]).unwrap();
        assert!(spec.url.ends_with("v1"));
    }

    #[test]
    fn mutates_headers() {
        let mut spec = HttpRequestSpec {
            headers: vec![("Accept".into(), "text/plain".into())],
            ..Default::default()
        };
        run_pre_script(
            r#"req.headers["X-Test"] = "1"; req.headers["Accept"] = "application/json";"#,
            &mut spec,
            &[],
        )
        .unwrap();
        assert!(spec.headers.iter().any(|(k, v)| k == "X-Test" && v == "1"));
        assert!(spec
            .headers
            .iter()
            .any(|(k, v)| k == "Accept" && v == "application/json"));
    }
}
