//! UDP connect and listen.

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::frame::Direction;
use crate::transport::{CmdRx, IoCommand, IoEvent, IoTx};

pub async fn run_udp_connect(host: &str, port: u16, io_tx: IoTx, mut cmd_rx: CmdRx) -> Result<()> {
    let addr = format!("{host}:{port}");
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind ephemeral")?;
    sock.connect(&addr)
        .await
        .with_context(|| format!("connect {addr}"))?;
    let peer = addr.clone();
    let _ = io_tx.send(IoEvent::Connected { peer: peer.clone() });

    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            n = sock.recv(&mut buf) => {
                match n {
                    Ok(n) => {
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::In,
                            payload: Bytes::copy_from_slice(&buf[..n]),
                            peer: Some(peer.clone()),
                        });
                    }
                    Err(e) => {
                        let _ = io_tx.send(IoEvent::Error { message: e.to_string() });
                        break;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(IoCommand::Close) | None => break,
                    Some(IoCommand::Send { payload, .. }) | Some(IoCommand::Broadcast { payload }) => {
                        sock.send(&payload).await?;
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::Out,
                            payload,
                            peer: Some(peer.clone()),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn run_udp_listen(host: &str, port: u16, io_tx: IoTx, mut cmd_rx: CmdRx) -> Result<()> {
    let addr = format!("{host}:{port}");
    let sock = UdpSocket::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let _ = io_tx.send(IoEvent::Status {
        message: format!("udp listening on {addr}"),
    });
    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("listen:{addr}"),
    });

    let mut last_peer: Option<std::net::SocketAddr> = None;
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer)) => {
                        last_peer = Some(peer);
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::In,
                            payload: Bytes::copy_from_slice(&buf[..n]),
                            peer: Some(peer.to_string()),
                        });
                    }
                    Err(e) => {
                        let _ = io_tx.send(IoEvent::Error { message: e.to_string() });
                        break;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(IoCommand::Close) | None => break,
                    Some(IoCommand::Send { payload, .. }) | Some(IoCommand::Broadcast { payload }) => {
                        if let Some(peer) = last_peer {
                            sock.send_to(&payload, peer).await?;
                            let _ = io_tx.send(IoEvent::Frame {
                                direction: Direction::Out,
                                payload,
                                peer: Some(peer.to_string()),
                            });
                        } else {
                            let _ = io_tx.send(IoEvent::Error {
                                message: "no peer yet to reply to".into(),
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
