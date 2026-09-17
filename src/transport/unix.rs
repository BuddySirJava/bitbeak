//! UNIX domain socket connect and listen.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};

use crate::cli::FramingKind;
use crate::frame::Direction;
use crate::framing::{encode_outbound, FramingConfig, LengthPrefixedCodec, NewlineFramer};
use crate::transport::{CmdRx, IoCommand, IoEvent, IoTx};
use tokio_util::codec::Decoder;

pub async fn run_unix_connect(
    path: &Path,
    framing: FramingConfig,
    io_tx: IoTx,
    mut cmd_rx: CmdRx,
) -> Result<()> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connect {}", path.display()))?;
    let peer = path.display().to_string();
    let _ = io_tx.send(IoEvent::Connected { peer });
    let (mut reader, mut writer) = stream.into_split();
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
                    Some(IoCommand::Close) | None => break,
                    Some(IoCommand::Send { payload, .. }) | Some(IoCommand::Broadcast { payload }) => {
                        let encoded = encode_outbound(&framing, payload)?;
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

pub async fn run_unix_listen(
    path: &Path,
    framing: FramingConfig,
    io_tx: IoTx,
    mut cmd_rx: CmdRx,
) -> Result<()> {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    let _ = io_tx.send(IoEvent::Status {
        message: format!("listening on unix://{}", path.display()),
    });
    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("listen:{}", path.display()),
    });

    let clients: Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Bytes>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU64::new(1));

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(IoCommand::Close) | None => break,
                    Some(IoCommand::Send { payload, client_id }) => {
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
                    Some(IoCommand::Broadcast { payload }) => {
                        let encoded = encode_outbound(&framing, payload)?;
                        let map = clients.lock().await;
                        for tx in map.values() {
                            let _ = tx.send(encoded.clone());
                        }
                    }
                }
            }
            accept = listener.accept() => {
                let (stream, _) = accept.context("accept")?;
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                let peer = format!("client-{id}");
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
                                        if writer.write_all(&data).await.is_err() { break; }
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
    let _ = std::fs::remove_file(path);
    Ok(())
}

fn drain_frames(buf: &mut BytesMut, framing: &FramingConfig) -> Vec<Bytes> {
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
