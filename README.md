# BitBeak

<p align="center">
  <img src="BitBeak.svg" alt="BitBeak mascot" width="160" height="160" />
</p>

**Interactive terminal inspector and full-suite network testing TUI.**

## Features

- **Stream sessions:** TCP, UDP, UNIX, WebSocket (`ws`/`wss`), TLS (`tls://`)
- **HTTP/HTTPS client:** HTTP/1.1 + HTTP/2, timing waterfall, auth (Bearer/Basic/API key/OAuth2), cookies, forms / GraphQL, unary gRPC, Rhai pre-scripts, history
- **Mock HTTP server** with live route editor + disk persistence
- **Collections:** `{{var}}` env, Postman/OpenAPI import, curl/Rust codegen
- **Multi-client listen** and **TCP proxy/tap**
- **Diagnose:** DNS, TCP/TLS probe, ICMP (TCP fallback)
- **Capture:** live sniff (Linux AF_PACKET + TPACKET_V3, macOS BPF, Windows Npcap), pcap/pcapng, protocol tree, capture + display filters (Wireshark subset), follow streams, TLS/QUIC decrypt helpers, rpcap, optional GeoIP/manuf
- **Bench**, **fuzz**, **pcap export** · btop-style UX

## Platforms

| OS | Live capture | Notes |
| --- | --- | --- |
| Linux | AF_PACKET (+ TPACKET_V3 negotiate) | Needs `CAP_NET_RAW` |
| macOS | BPF (`/dev/bpf*`) + `BIOCSETF` when filter compiles | Needs root or BPF group |
| Windows | Npcap (`wpcap.dll`) | Official installer on first live capture |

## Quick start

```bash
cargo build --release
bitbeak --help

bitbeak https://example.com/
bitbeak --import ./collection.postman_collection.json
bitbeak --codegen demo --codegen-lang curl
bitbeak --capture any
bitbeak --open ./trace.pcapng --keylog "$SSLKEYLOGFILE"
```

Full guides: **[Documentation](docs/index.md)** — [install](docs/install.md), [sessions](docs/sessions.md), [HTTP](docs/http.md), [capture](docs/capture.md), [filters](docs/filters.md), [collections](docs/collections.md), [palette](docs/palette.md).

Press **F1** in the TUI for help. Footer labels (`F1`–`F12`) are the source of truth.

## License

BitBeak is free software under the **GNU Affero General Public License v3 or later**.

Windows live capture uses [Npcap](https://npcap.com/) at runtime. Npcap is a separate product with its own license; BitBeak does not redistribute Npcap binaries.
