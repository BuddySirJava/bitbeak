//! Transport layer: TCP, UDP, UNIX, WebSocket, TLS connect/listen I/O tasks.

mod tcp;
mod tls;
mod udp;
mod websocket;

#[cfg(unix)]
mod unix;

pub use tcp::{run_tcp_connect, run_tcp_listen};
pub use tls::run_tls_connect;
pub use udp::{run_udp_connect, run_udp_listen};
pub use websocket::{run_ws_connect, run_ws_listen};

#[cfg(unix)]
pub use unix::{run_unix_connect, run_unix_listen};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::cli::Target;
use crate::framing::FramingConfig;

#[derive(Debug, Clone)]
pub enum IoEvent {
    Connected {
        peer: String,
    },
    Disconnected {
        reason: String,
    },
    Frame {
        direction: crate::frame::Direction,
        payload: Bytes,
        peer: Option<String>,
    },
    ClientJoined {
        id: u64,
        peer: String,
    },
    ClientLeft {
        id: u64,
    },
    Error {
        message: String,
    },
    Status {
        message: String,
    },
}

#[derive(Debug, Clone)]
pub enum IoCommand {
    Send {
        payload: Bytes,
        client_id: Option<u64>,
    },
    Broadcast {
        payload: Bytes,
    },
    Close,
}

pub type IoTx = mpsc::UnboundedSender<IoEvent>;
pub type IoRx = mpsc::UnboundedReceiver<IoEvent>;
pub type CmdTx = mpsc::UnboundedSender<IoCommand>;
pub type CmdRx = mpsc::UnboundedReceiver<IoCommand>;

pub fn channels() -> (IoTx, IoRx, CmdTx, CmdRx) {
    let (io_tx, io_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    (io_tx, io_rx, cmd_tx, cmd_rx)
}

/// Spawn the appropriate I/O task for a connect session.
pub fn spawn_connect(
    target: Target,
    framing: FramingConfig,
    io_tx: IoTx,
    cmd_rx: CmdRx,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let result = match target {
            Target::Tcp { host, port } => {
                run_tcp_connect(&host, port, framing, io_tx.clone(), cmd_rx).await
            }
            Target::Udp { host, port } => run_udp_connect(&host, port, io_tx.clone(), cmd_rx).await,
            #[cfg(unix)]
            Target::Unix { path } => run_unix_connect(&path, framing, io_tx.clone(), cmd_rx).await,
            #[cfg(not(unix))]
            Target::Unix { .. } => {
                let _ = io_tx.send(IoEvent::Error {
                    message: "UNIX sockets are not supported on this platform".into(),
                });
                Ok(())
            }
            Target::Ws { url, .. } => run_ws_connect(&url, io_tx.clone(), cmd_rx).await,
            Target::Tls { host, port } => {
                run_tls_connect(&host, port, framing, io_tx.clone(), cmd_rx).await
            }
            Target::Http { .. } => {
                let _ = io_tx.send(IoEvent::Error {
                    message: "HTTP targets use the HTTP session, not stream transport".into(),
                });
                Ok(())
            }
        };
        if let Err(e) = result {
            let _ = io_tx.send(IoEvent::Error {
                message: format!("{e:#}"),
            });
            let _ = io_tx.send(IoEvent::Disconnected {
                reason: "error".into(),
            });
        }
    })
}

/// Spawn listen I/O for multi-client sessions.
pub fn spawn_listen(
    target: Target,
    framing: FramingConfig,
    io_tx: IoTx,
    cmd_rx: CmdRx,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let result = match target {
            Target::Tcp { host, port } => {
                run_tcp_listen(&host, port, framing, io_tx.clone(), cmd_rx).await
            }
            Target::Udp { host, port } => run_udp_listen(&host, port, io_tx.clone(), cmd_rx).await,
            #[cfg(unix)]
            Target::Unix { path } => run_unix_listen(&path, framing, io_tx.clone(), cmd_rx).await,
            #[cfg(not(unix))]
            Target::Unix { .. } => {
                let _ = io_tx.send(IoEvent::Error {
                    message: "UNIX sockets are not supported on this platform".into(),
                });
                Ok(())
            }
            Target::Ws { url, .. } => run_ws_listen(&url, io_tx.clone(), cmd_rx).await,
            other => {
                let _ = io_tx.send(IoEvent::Error {
                    message: format!("listen not supported for {}", other.display()),
                });
                Ok(())
            }
        };
        if let Err(e) = result {
            let _ = io_tx.send(IoEvent::Error {
                message: format!("{e:#}"),
            });
        }
    })
}
