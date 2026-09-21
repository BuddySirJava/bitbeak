---
layout: default
title: Capture
---

# Capture

[Docs home](index.md)

Wireshark-style packet capture inside the TUI: live sniff, open files, protocol tree, follow streams, TLS/QUIC decrypt helpers.

## Open a capture session

```bash
bitbeak --capture any
bitbeak --capture eth0 --capture-filter "tcp port 443"
bitbeak --open ./trace.pcapng --keylog "$SSLKEYLOGFILE"
```

Or in the TUI: **F2 → Capture / Open file**, or palette:

| Command | Action |
| --- | --- |
| `:` `capture eth0` | Live on interface |
| `:` `open /path/file.pcapng` | Open **pcap / pcapng** file |
| `:` `rpcap host[:port]` | Probe remote rpcap (**experimental**) |
| `:` `rpcap host[:port] iface` | Live via `rpcap://host:port/iface` (**experimental**) |

### File mode (honest limits)

- Formats: classic **pcap** and **pcapng** (Enhanced/Simple packets). Not gzip.
- Ring: only the last `--max-frames` packets are kept (default 10 000). Status shows `showing N/M` when truncated.
- Follow TCP/HTTP works on Ethernet, Linux SLL/`any`, Raw, and Null/loopback. 802.11 follow is not a goal.
- **F6** is disabled on files (no live restart). Use **F8** display filter — `: cfilter` is live-only.
- Save: F12 / `: save` = displayed; `: save-all` = everything still in the ring.

## Keys (capture tab focused)

| Key | Action |
| --- | --- |
| **F6** | Start / stop live capture |
| **F8** | Display filter |
| **F12** | Save **displayed** packets as pcapng |
| `:` | Palette (follow, analysis overlays, cfilter, …) |

## Layout

- **Packets** — No / time / src / dst / proto / len / info (color rules apply)
- **Protocol tree** — Expandable dissection for the selected packet
- **Hex** — Bytes of selected (or decrypted) frame

## Capture vs display filters

- **Capture filter** (`:` `cfilter …` or `--capture-filter`) — tcpdump-style subset; may compile to kernel BPF when simple enough
- **Display filter** (**F8**) — Wireshark-*subset* on dissected packets after capture

Details and grammar: [Filters](filters.md).

## Follow & analysis (palette)

| Command | Action |
| --- | --- |
| `follow-tcp` / `follow-udp` / `follow-http` | Follow selected stream |
| `replay-http` | Follow HTTP (same overlay path) |
| `conversations` / `endpoints` / `hierarchy` / `expert` | Analysis overlays |
| `keylog` | Show keylog load status |
| `inject` | Inject selected packet (live, where supported) |
| `composer` | Capture composer helper |
| `export-objects` | Write HTTP objects from last `follow-http` to `~/.config/bitbeak/export/` |
| `names-toggle` | Toggle name/OUI resolution in the list |
| `manuf-reload` / `manuf-status` | Wireshark-style manuf file |
| `geoip-status` | MaxMind GeoLite2 status |

## TLS decrypt

Pass NSS-style keylog:

```bash
bitbeak --open trace.pcapng --keylog "$SSLKEYLOGFILE"
```

Supports TLS 1.2 / 1.3 application data when secrets are present. AES-128 and AES-256 suites are covered in the decrypt path.

## QUIC

- **Initial** packets: derived Initial keys + header protection; client and server keys tried
- **1-RTT:** best-effort when a QUIC traffic secret is in the keylog
- Not a full HTTP/3 stack

## Linux TPACKET_V3

AF_PACKET negotiates **TPACKET_V3** automatically when the kernel supports it; otherwise falls back.

## Remote capture (rpcap)

**Experimental.** Best-effort Wireshark rpcap client for remote sniff. Protocol coverage and server compatibility vary — treat as a convenience probe, not a supported production path.

## Optional data files

| Path | Purpose |
| --- | --- |
| `~/.config/bitbeak/GeoLite2-City.mmdb` | MaxMind GeoLite2 City (optional) |
| `~/.config/bitbeak/manuf` | Wireshark-style OUI lines, e.g. `F0:18:98:00:00:00/24\tApple, Inc.` |

## Disk ring

CLI `--ring-size MB` and `--ring-files N` enable a rotating on-disk capture ring (0 = disabled).
