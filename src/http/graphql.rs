//! GraphQL request body helpers.

use serde_json::{json, Value};

pub fn build_graphql_body(query: &str, variables: &str, operation: &str) -> Result<String, String> {
    let vars: Value = if variables.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(variables).map_err(|e| format!("variables JSON: {e}"))?
    };
    let mut obj = json!({
        "query": query,
        "variables": vars,
    });
    if !operation.trim().is_empty() {
        obj["operationName"] = Value::String(operation.trim().to_string());
    }
    serde_json::to_string_pretty(&obj).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_post_body() {
        let b = build_graphql_body("{ __typename }", r#"{"id":1}"#, "T").unwrap();
        assert!(b.contains("__typename"));
        assert!(b.contains("\"id\": 1") || b.contains("\"id\":1"));
        assert!(b.contains("operationName"));
    }
}
