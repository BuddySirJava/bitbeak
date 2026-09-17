//! TLS connection info extraction.

use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub peer_certs: Vec<CertSummary>,
    pub handshake_ms: u64,
}

#[derive(Debug, Clone)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sans: Vec<String>,
}

/// Perform a TLS handshake and collect certificate / cipher details.
pub async fn probe_tls(host: &str, port: u16) -> anyhow::Result<TlsInfo> {
    let start = std::time::Instant::now();
    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect(&addr).await?;

    let mut root = rustls::RootCertStore::empty();
    root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())?;
    let tls = connector.connect(server_name, stream).await?;
    let handshake_ms = start.elapsed().as_millis() as u64;

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
                    .and_then(|opt| opt)
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

    Ok(TlsInfo {
        version,
        cipher,
        alpn,
        peer_certs,
        handshake_ms,
    })
}

pub fn format_tls_info(info: &TlsInfo) -> Vec<String> {
    let mut lines = vec![
        format!("version:  {}", info.version),
        format!("cipher:   {}", info.cipher),
        format!("alpn:     {}", info.alpn.as_deref().unwrap_or("(none)")),
        format!("handshake: {} ms", info.handshake_ms),
        String::new(),
    ];
    for (i, cert) in info.peer_certs.iter().enumerate() {
        lines.push(format!("── cert #{i} ──"));
        lines.push(format!("subject: {}", cert.subject));
        lines.push(format!("issuer:  {}", cert.issuer));
        lines.push(format!("valid:   {} → {}", cert.not_before, cert.not_after));
        if !cert.sans.is_empty() {
            lines.push(format!("SANs:    {}", cert.sans.join(", ")));
        }
        lines.push(String::new());
    }
    let _ = Duration::from_millis(info.handshake_ms);
    lines
}
