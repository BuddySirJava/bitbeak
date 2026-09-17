//! HTTP client, cookies, assertions, history, GraphQL, gRPC, OAuth, scripts.

pub mod assert;
pub mod client;
pub mod cookies;
pub mod graphql;
pub mod grpc;
pub mod history;
pub mod oauth;
pub mod scripts;

pub use assert::{run_tests, AssertResult, RequestTest};
pub use client::{
    apply_auth, build_form_body, format_headers, parse_header_block, send_request, AuthKind,
    BodyMode, FormField, HttpRequestSpec, HttpResponse, HttpTimings, HttpVersion, RedirectHop,
};
pub use cookies::CookieJar;
pub use graphql::build_graphql_body;
pub use grpc::{
    decode_frames, derive_reply_type, encode_frame, json_to_protobuf, protobuf_to_json,
    reply_message_type, unary_call, GrpcRequest, GrpcResponse,
};
pub use history::{append_history, list_history, load_history_entry, HistoryEntry};
pub use oauth::{authorize_url, exchange_code, open_browser, wait_for_code, OAuthConfig};
pub use scripts::run_pre_script;
