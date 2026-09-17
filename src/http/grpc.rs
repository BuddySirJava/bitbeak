//! Unary gRPC over HTTP/2 (length-prefixed protobuf frames).

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};

#[derive(Debug, Clone)]
pub struct GrpcRequest {
    pub url: String, // https://host/package.Service/Method
    pub message: Bytes,
    pub authority: String,
}

#[derive(Debug, Clone)]
pub struct GrpcResponse {
    pub grpc_status: i32,
    pub grpc_message: String,
    pub message: Bytes,
    pub headers: Vec<(String, String)>,
}

fn load_pool(descriptor_path: &Path) -> Result<DescriptorPool> {
    let bytes = fs::read(descriptor_path)
        .with_context(|| format!("read grpc descriptor {}", descriptor_path.display()))?;
    DescriptorPool::decode(bytes.as_slice()).context("decode file descriptor set")
}

fn message_descriptor(pool: &DescriptorPool, message_type: &str) -> Result<MessageDescriptor> {
    pool.get_message_by_name(message_type)
        .with_context(|| format!("message type not found: {message_type}"))
}

/// Derive a reply message type from a request type (`FooRequest` → `FooResponse`).
pub fn derive_reply_type(message_type: &str) -> String {
    if let Some(base) = message_type.strip_suffix("Request") {
        format!("{base}Response")
    } else {
        message_type.to_string()
    }
}

/// Resolve the protobuf message type used to decode a gRPC response body.
pub fn reply_message_type(request_type: &str, explicit_reply_type: &str) -> String {
    if !explicit_reply_type.is_empty() {
        explicit_reply_type.to_string()
    } else {
        derive_reply_type(request_type)
    }
}

/// Encode JSON as protobuf bytes using a FileDescriptorSet on disk.
pub fn json_to_protobuf(descriptor_path: &Path, message_type: &str, json: &str) -> Result<Bytes> {
    let pool = load_pool(descriptor_path)?;
    let desc = message_descriptor(&pool, message_type)?;
    let mut deserializer = serde_json::de::Deserializer::from_str(json);
    let msg =
        DynamicMessage::deserialize(desc, &mut deserializer).context("parse json as protobuf")?;
    deserializer.end().context("trailing json in grpc body")?;
    Ok(Bytes::from(msg.encode_to_vec()))
}

/// Decode protobuf bytes to canonical JSON using a FileDescriptorSet on disk.
pub fn protobuf_to_json(
    descriptor_path: &Path,
    message_type: &str,
    bytes: &[u8],
) -> Result<String> {
    let pool = load_pool(descriptor_path)?;
    let desc = message_descriptor(&pool, message_type)?;
    let msg = DynamicMessage::decode(desc, bytes).context("decode grpc protobuf response")?;
    serde_json::to_string(&msg).context("encode grpc response as json")
}

/// Encode a single uncompressed gRPC data frame.
pub fn encode_frame(msg: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + msg.len());
    buf.put_u8(0); // compressed flag
    buf.put_u32(msg.len() as u32);
    buf.extend_from_slice(msg);
    buf.freeze()
}

pub fn decode_frames(data: &[u8]) -> Result<Vec<Bytes>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= data.len() {
        let _comp = data[i];
        let len = u32::from_be_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]) as usize;
        i += 5;
        if i + len > data.len() {
            bail!("truncated grpc frame");
        }
        out.push(Bytes::copy_from_slice(&data[i..i + len]));
        i += len;
    }
    Ok(out)
}

pub async fn unary_call(req: &GrpcRequest) -> Result<GrpcResponse> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http2()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let body = encode_frame(&req.message);
    let builder = Request::builder()
        .method("POST")
        .uri(&req.url)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "bitbeak-grpc/0.1");
    let http_req = builder.body(Full::new(body)).context("build grpc req")?;
    let resp = client.request(http_req).await.context("grpc request")?;
    let mut headers = Vec::new();
    for (k, v) in resp.headers().iter() {
        headers.push((
            k.as_str().to_string(),
            String::from_utf8_lossy(v.as_bytes()).into_owned(),
        ));
    }
    let collected = resp.into_body().collect().await.context("grpc body")?;
    let bytes = collected.to_bytes();
    let frames = decode_frames(&bytes).unwrap_or_default();
    let message = frames.into_iter().next().unwrap_or_default();
    let grpc_status = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("grpc-status"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let grpc_message = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("grpc-message"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    Ok(GrpcResponse {
        grpc_status,
        grpc_message,
        message,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };
    use tempfile::NamedTempFile;

    fn hello_descriptor_set() -> Vec<u8> {
        let file = FileDescriptorProto {
            name: Some("test.proto".into()),
            package: Some("test".into()),
            syntax: Some("proto3".into()),
            message_type: vec![
                DescriptorProto {
                    name: Some("HelloRequest".into()),
                    field: vec![FieldDescriptorProto {
                        name: Some("name".into()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("HelloResponse".into()),
                    field: vec![FieldDescriptorProto {
                        name: Some("greeting".into()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        FileDescriptorSet { file: vec![file] }.encode_to_vec()
    }

    fn write_descriptor_fixture() -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), hello_descriptor_set()).unwrap();
        file
    }

    #[test]
    fn frame_roundtrip() {
        let f = encode_frame(b"hello");
        let msgs = decode_frames(&f).unwrap();
        assert_eq!(&msgs[0][..], b"hello");
    }

    #[test]
    fn derive_reply_type_replaces_request_suffix() {
        assert_eq!(derive_reply_type("test.HelloRequest"), "test.HelloResponse");
        assert_eq!(derive_reply_type("test.Hello"), "test.Hello");
    }

    #[test]
    fn json_protobuf_roundtrip_via_descriptor() {
        let desc = write_descriptor_fixture();
        let bytes =
            json_to_protobuf(desc.path(), "test.HelloRequest", r#"{"name":"world"}"#).unwrap();
        let json = protobuf_to_json(desc.path(), "test.HelloRequest", &bytes).unwrap();
        assert_eq!(json, r#"{"name":"world"}"#);
    }

    #[test]
    fn protobuf_to_json_uses_response_type() {
        use prost_reflect::Value;

        let desc = write_descriptor_fixture();
        let pool = load_pool(desc.path()).unwrap();
        let resp_desc = message_descriptor(&pool, "test.HelloResponse").unwrap();
        let mut response = DynamicMessage::new(resp_desc);
        response.set_field_by_name("greeting", Value::String("hello bitbeak".into()));
        let json =
            protobuf_to_json(desc.path(), "test.HelloResponse", &response.encode_to_vec()).unwrap();
        assert_eq!(json, r#"{"greeting":"hello bitbeak"}"#);
        assert_eq!(
            reply_message_type("test.HelloRequest", ""),
            "test.HelloResponse"
        );
    }
}
