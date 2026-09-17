---
layout: default
title: Sessions
---

# Sessions

[Docs home](index.md)

BitBeak is a multi-tab workspace. Open a session with **F2** / `[+]`, the command palette (`:`), or a CLI flag.

## Session kinds

| Kind | How to open | Example URI / input |
| --- | --- | --- |
| Stream | New → Stream, or `:` `stream …` | `tcp://127.0.0.1:9090`, `unix:///tmp/app.sock`, `ws://host/path`, `tls://host:443` |
| HTTP / HTTPS | New → HTTP, or `:` `http …` | `https://api.example.com/v1/health` |
| Listen | New → Listen, or `:` `listen …` | `tcp://0.0.0.0:9090` |
| Proxy / tap | New → Proxy (bind + upstream) | bind `tcp://127.0.0.1:8080`, upstream `tcp://…` |
| Diagnose | New → Diagnose, or `:` `diag …` | `dns://example.com`, `ping://8.8.8.8`, `tcp://host:443`, `tls://host:443` |
| Capture (live) | New → Capture, or `--capture` / `:` `capture …` | `eth0`, `en0`, `any` |
| Open capture file | New → Open file, or `--open` / `:` `open …` | `/path/to/trace.pcapng` |
| Mock HTTP | New → Mock, or `:` `mock` / `:` `mock tcp://…` | default `tcp://127.0.0.1:18080` |

Paste a bare URI into the palette (`:`) — `http(s)://` opens HTTP; other schemes open Stream.

## Stream

- Composer + frame log + inspector (hex / text / JSON / MsgPack, …)
- Framing: CLI `--framing none|newline|length-prefixed` (prefix size/endian for LP)
- Hex mode: **Ctrl+M**; escapes `\x00`, `\n`, `\r`, `\t`, `\\`
- **F6** replay selected frame; **F11** fuzz; **F12** pcap export of session frames when configured

## Listen

- Multi-client accept on a bind URI
- Client list + shared log; optional **Broadcast** fan-out from the composer
- Same framing options as Stream

## Proxy / tap

- Local bind + upstream; traffic appears as proxied flows
- `--tls-intercept` is for local debug only (CLI)

## Diagnose

Probes without a full stream session:

- `dns://host` — resolve
- `ping://host[:port]` — ICMP with TCP fallback where needed
- `tcp://host:port` / `tls://host:port` — connect / TLS handshake timing
- `trace://…` — trace-style probe when used

## Mock HTTP

- In-process HTTP server with an editable route table (method, path, body, status, latency)
- Routes persist under `~/.config/bitbeak/mocks/<bind>.toml`
- Focus the routes pane with **Tab**; **a** add / **d** delete

## Capture

See [Capture](capture.md). Summary: live iface or open file → packet list, protocol tree, hex; **F6** start/stop; **F8** display filter; **F12** save displayed packets.

## Navigation (all sessions)

| Key | Action |
| --- | --- |
| **F1** | Help |
| **F2** | New session |
| **F3** / **F4** | Prev / next tab |
| **F5** | Cycle inspector format (where applicable) |
| **F8** | Filter |
| **F9** | Collections |
| **F10** | Quit prompt |
| **Tab** / **Shift+Tab** | Cycle panes |
| **Esc** | Close overlay / clear filter |
| **Ctrl+T** / **Ctrl+W** | New tab / close tab |
| `:` | Command palette |

Footer labels win when they disagree with memory.
