//! CLI parsing and URI target types.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{Parser, ValueEnum};
use thiserror::Error;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "bitbeak",
    version,
    about = "Interactive terminal inspector and full-suite network testing TUI"
)]
pub struct Args {
    /// Target URI (tcp://, udp://, unix://, ws://, wss://, tls://, http://, https://)
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Bind and wait for clients (listen session)
    #[arg(long)]
    pub listen: bool,

    /// Local bind URI for proxy mode
    #[arg(long)]
    pub proxy: Option<String>,

    /// Upstream URI for proxy mode
    #[arg(long)]
    pub upstream: Option<String>,

    /// Enable TLS intercept for proxy (local debug only)
    #[arg(long)]
    pub tls_intercept: bool,

    /// Open a diagnose session (dns://host or ping://host[:port])
    #[arg(long)]
    pub diag: Option<String>,

    /// Framing for TCP/UNIX streams
    #[arg(long, value_enum, default_value_t = FramingKind::None)]
    pub framing: FramingKind,

    /// Length-prefix size in bytes
    #[arg(long, default_value_t = 4)]
    pub prefix_size: u8,

    /// Length-prefix endianness
    #[arg(long, value_enum, default_value_t = Endian::Big)]
    pub prefix_endian: Endian,

    /// Max frames kept in the ring buffer
    #[arg(long, default_value_t = 10_000)]
    pub max_frames: usize,

    /// Write session frames to this pcap path
    #[arg(long)]
    pub pcap: Option<PathBuf>,

    /// Load a named collection or path
    #[arg(long)]
    pub collection: Option<String>,

    /// Import Postman v2.1 / OpenAPI 3 file into a collection (then exit)
    #[arg(long, value_name = "PATH")]
    pub import: Option<PathBuf>,

    /// Generate curl|rust code from a collection name/path
    #[arg(long, value_name = "COLLECTION")]
    pub codegen: Option<String>,

    /// Codegen language: curl or rust
    #[arg(long, default_value = "curl")]
    pub codegen_lang: String,

    /// Start a live capture session on IFACE (e.g. eth0, en0, any)
    #[arg(long)]
    pub capture: Option<String>,

    /// Capture filter (tcpdump subset)
    #[arg(long)]
    pub capture_filter: Option<String>,

    /// Open a pcap/pcapng file as a Capture session
    #[arg(long)]
    pub open: Option<PathBuf>,

    /// NSS SSLKEYLOGFILE path for TLS decrypt
    #[arg(long)]
    pub keylog: Option<PathBuf>,

    /// Rotating disk ring size in MB per file (0 = disabled)
    #[arg(long, default_value_t = 0)]
    pub ring_size: u64,

    /// Number of files in the rotating disk ring
    #[arg(long, default_value_t = 4)]
    pub ring_files: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum FramingKind {
    #[default]
    None,
    Newline,
    #[value(name = "length-prefixed")]
    LengthPrefixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum Endian {
    #[default]
    Big,
    Little,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Tcp { host: String, port: u16 },
    Udp { host: String, port: u16 },
    Unix { path: PathBuf },
    Ws { url: String, secure: bool },
    Tls { host: String, port: u16 },
    Http { url: String, secure: bool },
}

impl Target {
    pub fn display(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp://{host}:{port}"),
            Self::Udp { host, port } => format!("udp://{host}:{port}"),
            Self::Unix { path } => format!("unix://{}", path.display()),
            Self::Ws { url, .. } => url.clone(),
            Self::Tls { host, port } => format!("tls://{host}:{port}"),
            Self::Http { url, .. } => url.clone(),
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "TCP",
            Self::Udp { .. } => "UDP",
            Self::Unix { .. } => "UNIX",
            Self::Ws { secure: false, .. } => "WS",
            Self::Ws { secure: true, .. } => "WSS",
            Self::Tls { .. } => "TLS",
            Self::Http { secure: false, .. } => "HTTP",
            Self::Http { secure: true, .. } => "HTTPS",
        }
    }

    pub fn is_http(&self) -> bool {
        matches!(self, Self::Http { .. })
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp { host, port } | Self::Udp { host, port } | Self::Tls { host, port } => host
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, *port)),
            _ => None,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display())
    }
}

#[derive(Debug, Error)]
pub enum TargetParseError {
    #[error("empty target URI")]
    Empty,
    #[error("missing scheme in URI: {0}")]
    MissingScheme(String),
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("invalid host/port in URI: {0}")]
    InvalidHostPort(String),
    #[error("unix URI requires a path")]
    MissingUnixPath,
    #[error("invalid port: {0}")]
    InvalidPort(String),
}

impl FromStr for Target {
    type Err = TargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_target(s)
    }
}

/// Parse a bitbeak target URI.
pub fn parse_target(input: &str) -> Result<Target, TargetParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(TargetParseError::Empty);
    }

    let (scheme, rest) = s
        .split_once("://")
        .ok_or_else(|| TargetParseError::MissingScheme(s.to_string()))?;

    match scheme.to_ascii_lowercase().as_str() {
        "tcp" => {
            let (host, port) = split_host_port(rest)?;
            Ok(Target::Tcp { host, port })
        }
        "udp" => {
            let (host, port) = split_host_port(rest)?;
            Ok(Target::Udp { host, port })
        }
        "tls" => {
            let (host, port) = split_host_port(rest)?;
            Ok(Target::Tls { host, port })
        }
        "unix" => {
            let path = rest.trim_start_matches('/');
            // unix:///tmp/foo.sock → /tmp/foo.sock ; unix://tmp/foo → /tmp/foo if absolute intent
            let path = if rest.starts_with('/') {
                PathBuf::from(rest)
            } else if path.is_empty() {
                return Err(TargetParseError::MissingUnixPath);
            } else {
                PathBuf::from(format!("/{path}"))
            };
            if path.as_os_str().is_empty() || path == Path::new("/") {
                return Err(TargetParseError::MissingUnixPath);
            }
            Ok(Target::Unix { path })
        }
        "ws" => Ok(Target::Ws {
            url: s.to_string(),
            secure: false,
        }),
        "wss" => Ok(Target::Ws {
            url: s.to_string(),
            secure: true,
        }),
        "http" => Ok(Target::Http {
            url: s.to_string(),
            secure: false,
        }),
        "https" => Ok(Target::Http {
            url: s.to_string(),
            secure: true,
        }),
        other => Err(TargetParseError::UnsupportedScheme(other.to_string())),
    }
}

fn split_host_port(rest: &str) -> Result<(String, u16), TargetParseError> {
    // Strip optional path for tcp/udp/tls (ignore path)
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(TargetParseError::InvalidHostPort(rest.to_string()));
    }

    // IPv6: [addr]:port
    if let Some(inner) = authority.strip_prefix('[') {
        let (host, port_part) = inner
            .split_once("]:")
            .ok_or_else(|| TargetParseError::InvalidHostPort(authority.to_string()))?;
        let port = port_part
            .parse::<u16>()
            .map_err(|_| TargetParseError::InvalidPort(port_part.to_string()))?;
        return Ok((host.to_string(), port));
    }

    let (host, port_str) = authority
        .rsplit_once(':')
        .ok_or_else(|| TargetParseError::InvalidHostPort(authority.to_string()))?;
    if host.is_empty() {
        return Err(TargetParseError::InvalidHostPort(authority.to_string()));
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| TargetParseError::InvalidPort(port_str.to_string()))?;
    Ok((host.to_string(), port))
}

/// Format host:port, bracketing IPv6 so `::1:443` is not ambiguous.
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagSpec {
    Dns { host: String },
    Ping { host: String, port: Option<u16> },
    Tcp { host: String, port: u16 },
    Tls { host: String, port: u16 },
    Trace { host: String, port: Option<u16> },
}

impl FromStr for DiagSpec {
    type Err = TargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_diag(s)
    }
}

pub fn parse_diag(input: &str) -> Result<DiagSpec, TargetParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(TargetParseError::Empty);
    }
    if let Some(rest) = s.strip_prefix("dns://") {
        return Ok(DiagSpec::Dns {
            host: rest.to_string(),
        });
    }
    if let Some(rest) = s.strip_prefix("ping://") {
        return parse_ping_like(rest, |host, port| DiagSpec::Ping { host, port });
    }
    if let Some(rest) = s.strip_prefix("trace://") {
        return parse_ping_like(rest, |host, port| DiagSpec::Trace { host, port });
    }
    if let Some(rest) = s.strip_prefix("tcp://") {
        let (host, port) = split_host_port(rest)?;
        return Ok(DiagSpec::Tcp { host, port });
    }
    if let Some(rest) = s.strip_prefix("tls://") {
        let (host, port) = split_host_port(rest)?;
        return Ok(DiagSpec::Tls { host, port });
    }
    // bare host → DNS
    Ok(DiagSpec::Dns {
        host: s.to_string(),
    })
}

fn parse_ping_like<F>(rest: &str, f: F) -> Result<DiagSpec, TargetParseError>
where
    F: FnOnce(String, Option<u16>) -> DiagSpec,
{
    if rest.contains(':') && !rest.starts_with('[') {
        let (host, port) = split_host_port(rest)?;
        Ok(f(host, Some(port)))
    } else if let Some(inner) = rest.strip_prefix('[') {
        let (host, port) = split_host_port(&format!("[{inner}"))?;
        Ok(f(host, Some(port)))
    } else {
        Ok(f(rest.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_ipv4() {
        let t = parse_target("tcp://127.0.0.1:9090").unwrap();
        assert_eq!(
            t,
            Target::Tcp {
                host: "127.0.0.1".into(),
                port: 9090
            }
        );
    }

    #[test]
    fn parse_tcp_ipv6() {
        let t = parse_target("tcp://[::1]:8080").unwrap();
        assert_eq!(
            t,
            Target::Tcp {
                host: "::1".into(),
                port: 8080
            }
        );
    }

    #[test]
    fn parse_unix() {
        let t = parse_target("unix:///tmp/engine.sock").unwrap();
        assert_eq!(
            t,
            Target::Unix {
                path: PathBuf::from("/tmp/engine.sock")
            }
        );
    }

    #[test]
    fn parse_ws_wss() {
        assert!(matches!(
            parse_target("ws://localhost:8080/v1").unwrap(),
            Target::Ws { secure: false, .. }
        ));
        assert!(matches!(
            parse_target("wss://example.com/live").unwrap(),
            Target::Ws { secure: true, .. }
        ));
    }

    #[test]
    fn parse_http_https() {
        assert!(matches!(
            parse_target("https://api.example.com/v1").unwrap(),
            Target::Http { secure: true, .. }
        ));
    }

    #[test]
    fn parse_diag_dns() {
        assert_eq!(
            parse_diag("dns://example.com").unwrap(),
            DiagSpec::Dns {
                host: "example.com".into()
            }
        );
    }

    #[test]
    fn join_host_port_brackets_ipv6() {
        assert_eq!(join_host_port("127.0.0.1", 80), "127.0.0.1:80");
        assert_eq!(join_host_port("::1", 443), "[::1]:443");
        assert_eq!(join_host_port("[::1]", 443), "[::1]:443");
    }
}
