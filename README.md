<div align="center">

<img src="BitBeak.svg" alt="BitBeak mascot" width="160" height="160" />

# BitBeak

**Interactive terminal inspector and full-suite network testing TUI.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg?style=flat-square)](#platform-support)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![CI](https://img.shields.io/github/actions/workflow/status/BuddySirJava/bitbeak/ci.yml?branch=main&style=flat-square)](https://github.com/BuddySirJava/bitbeak/actions)

[Installation](#installation) · [Quick start](#quick-start) · [Features](#key-features) · [Docs](docs/index.md)

</div>

---

HTTP client, packet capture, stream inspector, mock server, proxy tap, and DNS/ping/TLS probes in one keyboard-driven binary.

## Highlights

* **Keyboard-driven TUI** — multi-tab workspace, F-key shortcuts, and a `:` command palette (btop-style).
* **HTTP / API workbench** — HTTP/1.1 and HTTP/2, GraphQL, unary gRPC, auth, cookies, history, and a timing waterfall.
* **Live capture** — Linux `AF_PACKET` (TPACKET_V3 when the kernel supports it), macOS BPF, Windows Npcap.
* **TLS / QUIC helpers** — dissect application data when an NSS-style `SSLKEYLOGFILE` is available.
* **Mocks, listen, and proxy** — in-process HTTP mock with a live route editor, multi-client listen, and TCP tap.

## Key Features

* **Stream sessions**
  * TCP, UDP, UNIX domain sockets, TLS (`tls://`), WebSocket (`ws://`, `wss://`).
  * Framing: none, newline, or length-prefixed. Hex composer, replay, fuzz, optional pcap export.
* **HTTP & APIs**
  * HTTP/1.1 and HTTP/2 (ALPN), urlencoded / multipart forms, GraphQL, unary gRPC (optional protobuf descriptors).
  * Auth: Bearer, Basic, API key (header or query), OAuth2 authorization-code loopback.
  * Rhai pre-request scripts, cookie jar, request history, sequential bench (`F7`).
  * Timing waterfall: DNS, TCP handshake, TLS, TTFB.
* **Capture & analysis**
  * Live sniff, `pcap` / `pcapng` open/save, remote capture via `rpcap`.
  * Capture filters (tcpdump subset) and display filters (Wireshark subset).
  * Protocol tree, follow TCP/UDP/HTTP, reassembly, TLS 1.2/1.3 and QUIC decrypt helpers.
  * Optional GeoIP (`GeoLite2-City.mmdb`) and Wireshark-style `manuf` OUI names.
* **Diagnostics, mocks & tooling**
  * Mock HTTP server with editable routes persisted under `~/.config/bitbeak/mocks/`.
  * Multi-client listen and bidirectional TCP proxy / tap (`--tls-intercept` for local debug).
  * Diagnose: `dns://`, `ping://` (ICMP with TCP fallback), `tcp://`, `tls://`, `trace://`.
* **Collections**
  * Named requests and environments with `{{var}}` substitution.
  * Import Postman v2.1 and OpenAPI 3; generate `curl` or Rust stubs under `./bitbeak-out/`.

## Platform Support

| Operating System | Packet engine | Privilege requirements |
| :--- | :--- | :--- |
| **Linux** | `AF_PACKET` (+ TPACKET_V3 when available) | `CAP_NET_RAW` (or root). Example: `sudo setcap cap_net_raw+ep ./target/release/bitbeak` |
| **macOS** | BPF (`/dev/bpf*`); `BIOCSETF` when a filter compiles | Root or membership in the BPF group |
| **Windows** | Npcap (`wpcap.dll`) | [Npcap](https://npcap.com/) installed; BitBeak can launch the official installer on first live capture |

## Installation

Rust **1.85+**. On Linux, also install `cmake`, `clang`, and `pkg-config` (needed by `aws-lc-rs`).

### From source

```bash
git clone https://github.com/BuddySirJava/bitbeak.git
cd bitbeak
cargo build --release
./target/release/bitbeak --help
```

Install into `~/.cargo/bin`:

```bash
cargo install --path .
```

Release binaries for Linux (gnu/musl), macOS, and Windows are built from git tags (`v*`) via GitHub Actions.

## Quick start

```bash
bitbeak https://example.com/
bitbeak --import ./tests/fixtures/postman_demo.json
bitbeak --codegen demo --codegen-lang curl
bitbeak --capture any
bitbeak --open ./trace.pcapng --keylog "$SSLKEYLOGFILE"
```

`--import` and `--codegen` exit after completing (no TUI).

Press **F1** in the TUI for help. Footer labels (`F1`–`F12`) are the source of truth for shortcuts.

Full guides: **[Documentation](docs/index.md)** — [install](docs/install.md), [sessions](docs/sessions.md), [HTTP](docs/http.md), [capture](docs/capture.md), [filters](docs/filters.md), [collections](docs/collections.md), [palette](docs/palette.md).

## License

BitBeak is free software under the **GNU Affero General Public License v3 or later**.

Windows live capture uses [Npcap](https://npcap.com/) at runtime. Npcap is a separate product with its own license; BitBeak does not redistribute Npcap binaries.
