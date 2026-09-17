//! Integration smokes for transports and HTTP.

use std::time::Duration;

use bitbeak::cli::{parse_target, FramingKind, Target};
use bitbeak::frame::{Direction, FrameBuffer};
use bitbeak::framing::{encode_outbound, FramingConfig, LengthPrefixedCodec};
use bitbeak::http::{send_request, HttpRequestSpec};
use bitbeak::session::SessionView;
use bitbeak::transport::{channels, IoCommand, IoEvent};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio_util::codec::{Decoder, Encoder};

#[cfg(unix)]
#[tokio::test]
async fn unix_echo_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("echo.sock");
    let listener = UnixListener::bind(&path).unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
    });

    let (io_tx, mut io_rx, cmd_tx, cmd_rx) = channels();
    let target = Target::Unix { path: path.clone() };
    let framing = FramingConfig {
        kind: FramingKind::None,
        ..Default::default()
    };
    let _h = bitbeak::transport::spawn_connect(target, framing, io_tx, cmd_rx);

    // wait connected
    let mut connected = false;
    for _ in 0..50 {
        if let Ok(IoEvent::Connected { .. }) = io_rx.try_recv() {
            connected = true;
            break;
        }
        if let Ok(IoEvent::Error { message }) = io_rx.try_recv() {
            panic!("connect error: {message}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(connected, "should connect");

    cmd_tx
        .send(IoCommand::Send {
            payload: Bytes::from_static(b"ping"),
            client_id: None,
        })
        .unwrap();

    let mut saw_out = false;
    let mut saw_in = false;
    for _ in 0..100 {
        while let Ok(ev) = io_rx.try_recv() {
            match ev {
                IoEvent::Frame {
                    direction: Direction::Out,
                    payload,
                    ..
                } => {
                    assert_eq!(&payload[..], b"ping");
                    saw_out = true;
                }
                IoEvent::Frame {
                    direction: Direction::In,
                    payload,
                    ..
                } => {
                    assert_eq!(&payload[..], b"ping");
                    saw_in = true;
                }
                _ => {}
            }
        }
        if saw_out && saw_in {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(saw_out && saw_in, "echo frames missing");
    let _ = cmd_tx.send(IoCommand::Close);
}

#[tokio::test]
async fn tcp_listen_two_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let (io_tx, mut io_rx, cmd_tx, cmd_rx) = channels();
    let target = Target::Tcp {
        host: "127.0.0.1".into(),
        port,
    };
    let framing = FramingConfig::default();
    let _h = bitbeak::transport::spawn_listen(target, framing, io_tx, cmd_rx);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut c1 = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut c2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut joins = 0u32;
    while let Ok(ev) = io_rx.try_recv() {
        if matches!(ev, IoEvent::ClientJoined { .. }) {
            joins += 1;
        }
    }
    assert!(joins >= 2, "expected 2 clients, got {joins}");

    // send to first client via broadcast
    cmd_tx
        .send(IoCommand::Broadcast {
            payload: Bytes::from_static(b"hi"),
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut buf = [0u8; 8];
    let n1 = tokio::time::timeout(Duration::from_millis(500), c1.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n1], b"hi");
    let n2 = tokio::time::timeout(Duration::from_millis(500), c2.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n2], b"hi");
    let _ = cmd_tx.send(IoCommand::Close);
}

#[tokio::test]
async fn http_get_local() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        let _ = stream.write_all(resp).await;
    });

    let spec = HttpRequestSpec {
        method: "GET".into(),
        url: format!("http://127.0.0.1:{port}/"),
        headers: vec![],
        body: Bytes::new(),
        ..Default::default()
    };
    let resp = send_request(&spec).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(&resp.body[..], b"hello");
}

#[tokio::test]
async fn proxy_splice_echo() {
    // upstream echo
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_port = up.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = up.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });

    let bind = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_port = bind.local_addr().unwrap().port();
    drop(bind);

    let bind_t = Target::Tcp {
        host: "127.0.0.1".into(),
        port: bind_port,
    };
    let up_t = Target::Tcp {
        host: "127.0.0.1".into(),
        port: up_port,
    };
    let mut proxy = bitbeak::session::ProxySession::start(bind_t, up_t, 100, false);
    let mut rx = proxy.take_io_rx().unwrap();

    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", bind_port))
        .await
        .unwrap();
    client.write_all(b"proxy").await.unwrap();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"proxy");

    // drain some events
    let mut frames = 0;
    for _ in 0..20 {
        while let Ok(ev) = rx.try_recv() {
            proxy.on_io(ev);
            frames += 1;
        }
        if frames > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!proxy.frames.is_empty());
}

#[tokio::test]
async fn tcp_probe_localhost() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let mut diag = bitbeak::session::DiagSession::new(bitbeak::cli::DiagSpec::Tcp {
        host: "127.0.0.1".into(),
        port,
    });
    diag.run_now().await;
    let text = diag.lines.join("\n");
    assert!(text.contains("OK") || text.contains("TCP connect"));
}

#[test]
fn length_prefix_codec() {
    let mut codec = LengthPrefixedCodec::new(4, bitbeak::cli::Endian::Big, 1024);
    let mut buf = BytesMut::new();
    codec.encode(Bytes::from_static(b"abc"), &mut buf).unwrap();
    let out = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(&out[..], b"abc");
}

#[test]
fn framing_newline() {
    let cfg = FramingConfig {
        kind: FramingKind::Newline,
        ..Default::default()
    };
    let out = encode_outbound(&cfg, Bytes::from_static(b"x")).unwrap();
    assert_eq!(&out[..], b"x\n");
}

#[test]
fn parse_targets() {
    assert!(matches!(
        parse_target("unix:///tmp/a.sock").unwrap(),
        Target::Unix { .. }
    ));
    assert!(matches!(
        parse_target("wss://x/y").unwrap(),
        Target::Ws { secure: true, .. }
    ));
}

#[test]
fn frame_filter() {
    let mut buf = FrameBuffer::new(10);
    buf.push(Direction::Out, b"hello".as_slice());
    assert_eq!(buf.filtered("hel").len(), 1);
    assert_eq!(buf.filtered("hex:6865").len(), 1);
}
