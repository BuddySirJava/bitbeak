//! WebSocket connect and simple listen (HTTP upgrade).

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream,
};

use crate::frame::Direction;
use crate::transport::{CmdRx, IoCommand, IoEvent, IoTx};

pub async fn run_ws_connect(url: &str, io_tx: IoTx, mut cmd_rx: CmdRx) -> Result<()> {
    let (ws, _) = connect_async(url)
        .await
        .with_context(|| format!("websocket connect {url}"))?;
    let _ = io_tx.send(IoEvent::Connected {
        peer: url.to_string(),
    });
    run_ws_loop(ws, io_tx, &mut cmd_rx).await
}

async fn run_ws_loop(
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    io_tx: IoTx,
    cmd_rx: &mut CmdRx,
) -> Result<()> {
    let (mut write, mut read) = ws.split();
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::In,
                            payload: Bytes::copy_from_slice(t.as_bytes()),
                            peer: None,
                        });
                    }
                    Some(Ok(Message::Binary(b))) => {
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::In,
                            payload: b,
                            peer: None,
                        });
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        let _ = io_tx.send(IoEvent::Disconnected { reason: "close".into() });
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        let _ = io_tx.send(IoEvent::Error { message: e.to_string() });
                        break;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(IoCommand::Close) | None => {
                        let _ = write.close().await;
                        break;
                    }
                    Some(IoCommand::Send { payload, .. }) | Some(IoCommand::Broadcast { payload }) => {
                        let msg = if let Ok(s) = std::str::from_utf8(&payload) {
                            Message::Text(s.to_string().into())
                        } else {
                            Message::Binary(payload.to_vec().into())
                        };
                        write.send(msg).await?;
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::Out,
                            payload,
                            peer: None,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Listen: bind host:port from ws://host:port/path and accept one upgrade at a time (multi via spawn).
pub async fn run_ws_listen(url: &str, io_tx: IoTx, mut cmd_rx: CmdRx) -> Result<()> {
    let listen_addr = parse_ws_listen_addr(url)?;
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    let _ = io_tx.send(IoEvent::Status {
        message: format!("ws listening on {listen_addr}"),
    });
    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("listen:{listen_addr}"),
    });

    // Accept first client and run as single stream (multi-client full WS listen is simplified)
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(IoCommand::Close) | None => break,
                    _ => {}
                }
            }
            accept = listener.accept() => {
                let (stream, peer) = accept?;
                let _ = io_tx.send(IoEvent::ClientJoined {
                    id: 1,
                    peer: peer.to_string(),
                });
                let ws = accept_async(stream).await.context("ws accept")?;
                let (mut write, mut read) = ws.split();
                loop {
                    tokio::select! {
                        msg = read.next() => {
                            match msg {
                                Some(Ok(Message::Text(t))) => {
                                    let _ = io_tx.send(IoEvent::Frame {
                                        direction: Direction::In,
                                        payload: Bytes::copy_from_slice(t.as_bytes()),
                                        peer: Some(peer.to_string()),
                                    });
                                }
                                Some(Ok(Message::Binary(b))) => {
                                    let _ = io_tx.send(IoEvent::Frame {
                                        direction: Direction::In,
                                        payload: b,
                                        peer: Some(peer.to_string()),
                                    });
                                }
                                Some(Ok(Message::Close(_))) | None => {
                                    let _ = io_tx.send(IoEvent::ClientLeft { id: 1 });
                                    break;
                                }
                                Some(Ok(_)) => {}
                                Some(Err(e)) => {
                                    let _ = io_tx.send(IoEvent::Error { message: e.to_string() });
                                    break;
                                }
                            }
                        }
                        cmd = cmd_rx.recv() => {
                            match cmd {
                                Some(IoCommand::Close) | None => return Ok(()),
                                Some(IoCommand::Send { payload, .. }) | Some(IoCommand::Broadcast { payload }) => {
                                    let msg = if let Ok(s) = std::str::from_utf8(&payload) {
                                        Message::Text(s.to_string().into())
                                    } else {
                                        Message::Binary(payload.to_vec().into())
                                    };
                                    write.send(msg).await?;
                                    let _ = io_tx.send(IoEvent::Frame {
                                        direction: Direction::Out,
                                        payload,
                                        peer: Some(peer.to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn parse_ws_listen_addr(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.contains(':') {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:80"))
    }
}
