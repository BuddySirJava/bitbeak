---
layout: default
title: Install & build
---

# Install & build

[Docs home](index.md)

## Requirements

- Rust **1.85+** (see `rust-version` in `Cargo.toml`)
- Linux build extras for `aws-lc-rs`: `cmake`, `clang`, `pkg-config` (CI installs these on Ubuntu)

## Build

```bash
git clone https://github.com/bitbeak/bitbeak.git
cd bitbeak
cargo build --release
./target/release/bitbeak --help
```

Install to `~/.cargo/bin` if you prefer:

```bash
cargo install --path .
```

## Live capture privileges

| OS | Backend | Privileges |
| --- | --- | --- |
| Linux | AF_PACKET (+ TPACKET_V3 when the kernel supports it) | `CAP_NET_RAW` (or root). Example: `sudo setcap cap_net_raw+ep ./target/release/bitbeak` |
| macOS | BPF (`/dev/bpf*`); `BIOCSETF` when a filter compiles for the kernel | Root or membership in the BPF group |
| Windows | Npcap (`wpcap.dll`) | Npcap installed; BitBeak can launch the official installer on first live capture |

BitBeak does **not** redistribute Npcap binaries. Npcap has its [own license](https://npcap.com/).

## CLI overview

```text
bitbeak [TARGET]
  --listen
  --proxy URI --upstream URI [--tls-intercept]
  --diag dns://host | ping://host[:port] | …
  --framing none|newline|length-prefixed
  --prefix-size N --prefix-endian big|little
  --max-frames N
  --pcap PATH
  --collection NAME|PATH
  --import PATH          # Postman v2.1 / OpenAPI 3, then exit
  --codegen COLLECTION --codegen-lang curl|rust
  --capture IFACE [--capture-filter FILTER]
  --open PCAP [--keylog SSLKEYLOGFILE]
  --ring-size MB --ring-files N
```

URI schemes for stream/HTTP targets: `tcp://`, `udp://`, `unix://`, `ws://`, `wss://`, `tls://`, `http://`, `https://`.

## Next

- [Sessions](sessions.md) — open tabs from the TUI or CLI
- [Capture](capture.md) — sniff and open traces
