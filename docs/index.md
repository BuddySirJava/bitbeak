---
layout: default
title: BitBeak docs
---

<p align="center">
  <img src="assets/BitBeak.svg" alt="BitBeak mascot" width="140" height="140" />
</p>

# BitBeak documentation

**Keyboard network Swiss army knife** — HTTP, capture, streams, proxy, and diag in one binary. Blades hand off to each other (`: sniff` → follow → `r` replay). Not a Postman/Wireshark/mitmproxy clone.

Source: [github.com/bitbeak/bitbeak](https://github.com/bitbeak/bitbeak) · License: [AGPL-3.0-or-later](https://github.com/bitbeak/bitbeak/blob/master/LICENSE)

## Guides

| Guide | Contents |
| --- | --- |
| [Install & build](install.md) | Cargo build, privileges, Npcap / BPF / `CAP_NET_RAW` |
| [Sessions](sessions.md) | Stream, HTTP, listen, proxy, diagnose, capture tabs |
| [HTTP / GraphQL / gRPC](http.md) | Auth, body modes, scripts, history, OAuth |
| [Capture](capture.md) | Live sniff, pcap/pcapng, keylog, QUIC, rpcap, GeoIP, manuf |
| [Filters](filters.md) | Capture filter vs display filter (Wireshark subset) |
| [Collections](collections.md) | Env vars, import, codegen, config directory |
| [Command palette](palette.md) | Full `:` command reference |
| [Contributing](contributing.md) | fmt / clippy / test, Pages enablement, AGPL |

## Quick start

```bash
cargo build --release
./target/release/bitbeak --help

bitbeak https://example.com/
bitbeak --capture any
bitbeak --open ./trace.pcapng --keylog "$SSLKEYLOGFILE"
```

Press `F1` for in-app help. Footer labels (`F1`–`F12`) are the source of truth for shortcuts.
