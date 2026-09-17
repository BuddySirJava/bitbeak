//! TCP connect and multi-client listen.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::cli::FramingKind;
use crate::frame::Direction;
use crate::framing::{encode_outbound, FramingConfig, LengthPrefixedCodec, NewlineFramer};
use crate::transport::{CmdRx, IoEvent, IoTx};

pub async fn run_tcp_connect(
    host: &str,
    port: u16,
    framing: FramingConfig,
    io_tx: IoTx,
    mut cmd_rx: CmdRx,
) -> Result<()> {
    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("connect {addr}"))?;
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| addr.clone());
    let _ = io_tx.send(IoEvent::Connected { peer: peer.clone() });

    let (reader, writer) = stream.into_split();
    run_stream_io(reader, writer, framing, io_tx, &mut cmd_rx).await
}

pub async fn run_tcp_listen(
    host: &str,
    port: u16,
    framing: FramingConfig,
    io_tx: IoTx,
    mut cmd_rx: CmdRx,
) -> Result<()> {
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let _ = io_tx.send(IoEvent::Status {
        message: format!("listening on {addr}"),
    });
    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("listen:{addr}"),
    });

    let clients: Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Bytes>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU64::new(1));

    loop {
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(crate::transport::IoCommand::Close) | None => break,
                    Some(crate::transport::IoCommand::Send { payload, client_id }) => {
                        let encoded = encode_outbound(&framing, payload)?;
                        let map = clients.lock().await;
                        if let Some(id) = client_id {
                            if let Some(tx) = map.get(&id) {
                                let _ = tx.send(encoded);
                            }
                        } else if let Some((_, tx)) = map.iter().next() {
                            let _ = tx.send(encoded);
                        }
                    }
                    Some(crate::transport::IoCommand::Broadcast { payload }) => {
                        let encoded = encode_outbound(&framing, payload)?;
                        let map = clients.lock().await;
                        for tx in map.values() {
                            let _ = tx.send(encoded.clone());
                        }
                    }
                }
            }
            accept = listener.accept() => {
                let (stream, peer_addr) = accept.context("accept")?;
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                let peer = peer_addr.to_string();
                let _ = io_tx.send(IoEvent::ClientJoined { id, peer: peer.clone() });
                let (tx, mut rx) = mpsc::unbounded_channel::<Bytes>();
                clients.lock().await.insert(id, tx);
                let io_tx2 = io_tx.clone();
                let clients2 = clients.clone();
                let framing2 = framing.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.into_split();
                    let mut read_buf = BytesMut::with_capacity(4096);
                    loop {
                        tokio::select! {
                            n = reader.read_buf(&mut read_buf) => {
                                match n {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        for frame in drain_frames(&mut read_buf, &framing2) {
                                            let _ = io_tx2.send(IoEvent::Frame {
                                                direction: Direction::In,
                                                payload: frame,
                                                peer: Some(peer.clone()),
                                            });
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            msg = rx.recv() => {
                                match msg {
                                    Some(data) => {
                                        if writer.write_all(&data).await.is_err() {
                                            break;
                                        }
                                        let _ = io_tx2.send(IoEvent::Frame {
                                            direction: Direction::Out,
                                            payload: data,
                                            peer: Some(peer.clone()),
                                        });
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                    clients2.lock().await.remove(&id);
                    let _ = io_tx2.send(IoEvent::ClientLeft { id });
                });
            }
        }
    }
    Ok(())
}

async fn run_stream_io<R, W>(
    mut reader: R,
    mut writer: W,
    framing: FramingConfig,
    io_tx: IoTx,
    cmd_rx: &mut CmdRx,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut read_buf = BytesMut::with_capacity(8192);
    loop {
        tokio::select! {
            n = reader.read_buf(&mut read_buf) => {
                match n {
                    Ok(0) => {
                        let _ = io_tx.send(IoEvent::Disconnected { reason: "eof".into() });
                        break;
                    }
                    Ok(_) => {
                        for frame in drain_frames(&mut read_buf, &framing) {
                            let _ = io_tx.send(IoEvent::Frame {
                                direction: Direction::In,
                                payload: frame,
                                peer: None,
                            });
                        }
                    }
                    Err(e) => {
                        let _ = io_tx.send(IoEvent::Error { message: e.to_string() });
                        break;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(crate::transport::IoCommand::Close) | None => break,
                    Some(crate::transport::IoCommand::Send { payload, .. })
                    | Some(crate::transport::IoCommand::Broadcast { payload }) => {
                        let encoded = encode_outbound(&framing, payload.clone())?;
                        writer.write_all(&encoded).await?;
                        let _ = io_tx.send(IoEvent::Frame {
                            direction: Direction::Out,
                            payload: encoded,
                            peer: None,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn drain_frames(buf: &mut BytesMut, framing: &FramingConfig) -> Vec<Bytes> {
    use tokio_util::codec::Decoder;
    let mut out = Vec::new();
    match framing.kind {
        FramingKind::None => {
            if !buf.is_empty() {
                out.push(buf.split().freeze());
            }
        }
        FramingKind::Newline => {
            let mut codec = NewlineFramer::new(framing.max_frame);
            while let Ok(Some(item)) = codec.decode(buf) {
                out.push(item);
            }
        }
        FramingKind::LengthPrefixed => {
            let mut codec =
                LengthPrefixedCodec::new(framing.prefix_size, framing.endian, framing.max_frame);
            while let Ok(Some(item)) = codec.decode(buf) {
                out.push(item);
            }
        }
    }
    out
}
