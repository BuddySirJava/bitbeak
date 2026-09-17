---
layout: default
title: Filters
---

# Filters

[Docs home](index.md)

BitBeak has two filter layers. They are **not** full Wireshark / tcpdump parity.

## Capture filter

Applied while capturing (and may compile to kernel BPF when simple).

Set via:

- CLI: `--capture-filter 'tcp port 443'`
- Palette: `:` `cfilter tcp port 443`

Supported ideas (tcpdump subset):

| Construct | Examples |
| --- | --- |
| Protocol | `tcp`, `udp`, `icmp`, `arp`, `ip`, `ip6` |
| Host | `host 1.2.3.4`, `src host …`, `dst host …` |
| Port | `port 443`, `src port 53`, `dst port 80` |
| Net | IPv4 net/mask forms |
| Combinators | `and`, `or`, `not`, parentheses |

Complex filters may still match in-process when they are not “kernel simple”.

## Display filter

Applied to the packet list after dissection (**F8**). Empty filter = show all.

### Boolean structure

- `and` / `or` / `not`
- Parentheses: `(http or dns) and not udp`

### Protocol tokens

Bare names match dissected flags / protocol, including:

`http`, `http2`, `dns`, `mdns`, `llmnr`, `dhcp`, `tcp`, `udp`, `tls`, `websocket`, `sip`, `rtp`, `quic`, `wifi` / `wlan` / `802.11`, `arp`, `icmp`, `ip`, `ipv6`

### Address / port helpers

| Expression | Meaning |
| --- | --- |
| `ip.addr == 10.0.0.1` | Src or dst summary contains the address |
| `ipv6.addr == …` | Same for IPv6 text |
| `tcp.port == 443` | TCP src/dst port |
| `udp.port == 53` | UDP src/dst port |

### Field comparisons

Uses dissected field maps (and aliases):

```text
http.request.method == "GET"
http.request.method contains "GE"
http.request.method matches "^G"
http.request.method[0:2] == "GE"
http.request.method[0] == "G"
frame.len >= 100
```

Operators: `==`, `=`, `!=`, `<`, `>`, `<=`, `>=`, `contains`, `matches` (regex).

### Aliases

Convenience names resolve to summary or alternate field keys, including:

- `ip.src` / `ip.dst`
- `tcp.srcport` / `tcp.dstport` / `udp.srcport` / `udp.dstport`
- `http.host` → `http.request.host` / `Host` / …

### Limitations

This is a **Wireshark subset**, not full display-filter parity. Unknown protocol tokens fall back to case-insensitive protocol-name match on the summary. Prefer in-app help (**F1**) and trial filters on a small capture when unsure.
