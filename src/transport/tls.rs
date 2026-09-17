//! TLS-wrapped TCP connect.

use anyhow::{Context, Result};
use bytes::BytesMut;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::cli::FramingKind;
use crate::frame::Direction;
use crate::framing::{encode_outbound, FramingConfig, LengthPrefixedCodec, NewlineFramer};
use crate::transport::{CmdRx, IoCommand, IoEvent, IoTx};
use tokio_util::codec::Decoder;

pub async fn run_tls_connect(
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

    let mut root = rustls::RootCertStore::empty();
    root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .context("tls handshake")?;

    let _ = io_tx.send(IoEvent::Connected {
        peer: format!("tls://{host}:{port}"),
    });

    let (mut reader, mut writer) = tokio::io::split(tls);
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

fn drain_frames(buf: &mut BytesMut, framing: &FramingConfig) -> Vec<bytes::Bytes> {
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
