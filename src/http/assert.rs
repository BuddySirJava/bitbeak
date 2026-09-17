//! Post-response assertion DSL.

use serde::{Deserialize, Serialize};

use crate::http::HttpResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTest {
    /// e.g. "status == 200", "header Content-Type contains json", "body contains ok", "jsonpath $.id exists"
    pub expr: String,
}

#[derive(Debug, Clone)]
pub struct AssertResult {
    pub expr: String,
    pub passed: bool,
    pub detail: String,
}

pub fn run_tests(tests: &[RequestTest], resp: &HttpResponse) -> Vec<AssertResult> {
    tests.iter().map(|t| eval_one(&t.expr, resp)).collect()
}

fn eval_one(expr: &str, resp: &HttpResponse) -> AssertResult {
    let e = expr.trim();
    if let Some(rest) = e.strip_prefix("status") {
        return cmp_u16("status", rest, resp.status, e);
    }
    if let Some(rest) = e.strip_prefix("header ") {
        // header Name contains|== value
        let rest = rest.trim();
        if let Some((name, op_val)) = rest.split_once(' ') {
            let name = name.trim();
            let val = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            return str_op(e, val, op_val.trim());
        }
    }
    if let Some(rest) = e.strip_prefix("body ") {
        let body = String::from_utf8_lossy(&resp.body);
        return str_op(e, &body, rest.trim());
    }
    if let Some(rest) = e.strip_prefix("jsonpath ") {
        // jsonpath $.id exists | jsonpath $.a == b
        let rest = rest.trim();
        let (path, op) = if let Some((p, o)) = rest.split_once(' ') {
            (p.trim(), o.trim())
        } else {
            (rest, "exists")
        };
        let found = json_pointer(&resp.body, path);
        if op == "exists" {
            let ok = found.is_some();
            return AssertResult {
                expr: e.into(),
                passed: ok,
                detail: if ok {
                    "exists".into()
                } else {
                    "missing".into()
                },
            };
        }
        if let Some(rest) = op.strip_prefix("==") {
            let expect = rest.trim().trim_matches('"');
            let got = found.unwrap_or_default();
            let ok = got == expect;
            return AssertResult {
                expr: e.into(),
                passed: ok,
                detail: format!("got {got:?}"),
            };
        }
    }
    AssertResult {
        expr: e.into(),
        passed: false,
        detail: "unknown assertion".into(),
    }
}

fn cmp_u16(label: &str, rest: &str, actual: u16, expr: &str) -> AssertResult {
    let rest = rest.trim();
    let (op, val_s) = if let Some(v) = rest.strip_prefix("==") {
        ("==", v)
    } else if let Some(v) = rest.strip_prefix("!=") {
        ("!=", v)
    } else if let Some(v) = rest.strip_prefix(">=") {
        (">=", v)
    } else if let Some(v) = rest.strip_prefix("<=") {
        ("<=", v)
    } else if let Some(v) = rest.strip_prefix('>') {
        (">", v)
    } else if let Some(v) = rest.strip_prefix('<') {
        ("<", v)
    } else if let Some(v) = rest.strip_prefix('=') {
        ("==", v)
    } else {
        return AssertResult {
            expr: expr.into(),
            passed: false,
            detail: format!("bad {label} cmp"),
        };
    };
    let expect: u16 = match val_s.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            return AssertResult {
                expr: expr.into(),
                passed: false,
                detail: "bad number".into(),
            }
        }
    };
    let ok = match op {
        "==" => actual == expect,
        "!=" => actual != expect,
        ">" => actual > expect,
        "<" => actual < expect,
        ">=" => actual >= expect,
        "<=" => actual <= expect,
        _ => false,
    };
    AssertResult {
        expr: expr.into(),
        passed: ok,
        detail: format!("{actual}"),
    }
}

fn str_op(expr: &str, hay: &str, op_val: &str) -> AssertResult {
    if let Some(v) = op_val.strip_prefix("contains ") {
        let needle = v.trim().trim_matches('"');
        let ok = hay
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase());
        return AssertResult {
            expr: expr.into(),
            passed: ok,
            detail: if ok {
                "matched".into()
            } else {
                "no match".into()
            },
        };
    }
    if let Some(v) = op_val.strip_prefix("==") {
        let expect = v.trim().trim_matches('"');
        let ok = hay == expect;
        return AssertResult {
            expr: expr.into(),
            passed: ok,
            detail: format!("got len={}", hay.len()),
        };
    }
    AssertResult {
        expr: expr.into(),
        passed: false,
        detail: "bad string op".into(),
    }
}

/// Minimal JSON pointer: $.a.b or $.a
fn json_pointer(body: &[u8], path: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let path = path.trim().trim_start_matches('$').trim_start_matches('.');
    if path.is_empty() {
        return Some(v.to_string());
    }
    let mut cur = &v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    match cur {
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Bytes::from(body.to_string()),
            timings: Default::default(),
            tls: None,
            redirect_chain: Vec::new(),
            version: "HTTP/1.1".into(),
        }
    }

    #[test]
    fn status_and_jsonpath() {
        let r = resp(200, r#"{"id":"42"}"#);
        let t = vec![
            RequestTest {
                expr: "status == 200".into(),
            },
            RequestTest {
                expr: "jsonpath $.id exists".into(),
            },
            RequestTest {
                expr: "header Content-Type contains json".into(),
            },
        ];
        let out = run_tests(&t, &r);
        assert!(out.iter().all(|a| a.passed));
    }
}
