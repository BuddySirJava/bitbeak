//! Hyper connector that records DNS / TCP / TLS timings on the live connection.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use hyper::rt::{Read, Write};
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;
use x509_parser::prelude::*;

use crate::http::{HttpTimings, HttpVersion};
use crate::tlsinfo::{CertSummary, TlsInfo};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Default)]
pub struct TimingCapture {
    pub timings: HttpTimings,
    pub tls: Option<TlsInfo>,
}

#[derive(Clone)]
pub struct TimedHttpsConnector {
    capture: Arc<Mutex<TimingCapture>>,
    tls_config: Arc<rustls::ClientConfig>,
    http_version: HttpVersion,
}

impl TimedHttpsConnector {
    pub fn new(http_version: HttpVersion, capture: Arc<Mutex<TimingCapture>>) -> Self {
        let mut root = rustls::RootCertStore::empty();
        root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root)
            .with_no_client_auth();
        match http_version {
            HttpVersion::Http1 => {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }
            HttpVersion::Http2 => {
                config.alpn_protocols = vec![b"h2".to_vec()];
            }
            HttpVersion::Auto => {
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
        }
        Self {
            capture,
            tls_config: Arc::new(config),
            http_version,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum TimedStream {
    Http(TokioIo<TcpStream>),
    Https(TokioIo<TlsStream<TcpStream>>),
}

impl Connection for TimedStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Http(s) => s.connected(),
            Self::Https(s) => {
                let (_, session) = s.inner().get_ref();
                if session.alpn_protocol() == Some(b"h2") {
                    Connected::new().negotiated_h2()
                } else {
                    Connected::new()
                }
            }
        }
    }
}

impl Read for TimedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Http(s) => Pin::new(s).poll_read(cx, buf),
            Self::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl Write for TimedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Http(s) => Pin::new(s).poll_write(cx, buf),
            Self::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Http(s) => Pin::new(s).poll_flush(cx),
            Self::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Http(s) => Pin::new(s).poll_shutdown(cx),
            Self::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Service<Uri> for TimedHttpsConnector {
    type Response = TimedStream;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<TimedStream, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let capture = self.capture.clone();
        let tls_config = self.tls_config.clone();
        let _http_version = self.http_version;
        Box::pin(async move {
            let scheme = dst.scheme_str().unwrap_or("http");
            let host = dst
                .host()
                .ok_or_else(|| std::io::Error::other("missing host"))?
                .to_string();
            let port = dst
                .port_u16()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });

            let dns_start = Instant::now();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| -> BoxError { e.into() })?
                .collect();
            let dns_ms = dns_start.elapsed().as_millis() as u64;
            if addrs.is_empty() {
                return Err(std::io::Error::other("no addresses").into());
            }
            {
                let mut g = capture.lock().unwrap_or_else(|e| e.into_inner());
                if g.timings.dns_ms.is_none() {
                    g.timings.dns_ms = Some(dns_ms);
                }
            }

            let tcp_start = Instant::now();
            let mut last_err = None;
            let mut stream = None;
            for addr in addrs {
                match TcpStream::connect(addr).await {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            let stream = stream.ok_or_else(|| {
                last_err.unwrap_or_else(|| std::io::Error::other("tcp connect failed"))
            })?;
            let tcp_ms = tcp_start.elapsed().as_millis() as u64;
            {
                let mut g = capture.lock().unwrap_or_else(|e| e.into_inner());
                if g.timings.tcp_ms.is_none() {
                    g.timings.tcp_ms = Some(tcp_ms);
                }
            }

            if scheme == "http" {
                return Ok(TimedStream::Http(TokioIo::new(stream)));
            }

            let tls_start = Instant::now();
            let connector = TlsConnector::from(tls_config);
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| -> BoxError { format!("invalid server name: {e}").into() })?;
            let tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| -> BoxError { e.into() })?;
            let handshake_ms = tls_start.elapsed().as_millis() as u64;
            let info = tls_info_from_stream(&tls, handshake_ms);
            {
                let mut g = capture.lock().unwrap_or_else(|e| e.into_inner());
                if g.timings.tls_ms.is_none() {
                    g.timings.tls_ms = Some(handshake_ms);
                }
                if g.tls.is_none() {
                    g.tls = Some(info);
                }
            }
            Ok(TimedStream::Https(TokioIo::new(tls)))
        })
    }
}

fn tls_info_from_stream(tls: &TlsStream<TcpStream>, handshake_ms: u64) -> TlsInfo {
    let (_, session) = tls.get_ref();
    let version = session
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    let cipher = session
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()))
        .unwrap_or_else(|| "unknown".into());
    let alpn = session
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let mut peer_certs = Vec::new();
    if let Some(certs) = session.peer_certificates() {
        for cert in certs.iter() {
            if let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) {
                let sans = parsed
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .map(|ext| {
                        ext.value
                            .general_names
                            .iter()
                            .filter_map(|gn| match gn {
                                GeneralName::DNSName(d) => Some(d.to_string()),
                                GeneralName::IPAddress(ip) => Some(format!("{ip:?}")),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                peer_certs.push(CertSummary {
                    subject: parsed.subject().to_string(),
                    issuer: parsed.issuer().to_string(),
                    not_before: parsed.validity().not_before.to_string(),
                    not_after: parsed.validity().not_after.to_string(),
                    sans,
                });
            }
        }
    }
    TlsInfo {
        version,
        cipher,
        alpn,
        peer_certs,
        handshake_ms,
    }
}
