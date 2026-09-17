---
layout: default
title: Command palette
---

# Command palette

[Docs home](index.md)

Press **`:`** to open the palette. Enter runs the command; Esc cancels.

Bare URIs are accepted: `https://…` opens HTTP; other `scheme://` targets open Stream when parseable.

## Global

| Command | Action |
| --- | --- |
| `help` | Help overlay |
| `quit` | Quit confirmation |
| `stream URI` | Open stream session |
| `http URI` | Open HTTP session |
| `listen URI` | Open listen session |
| `proxy …` | Open proxy URI entry path |
| `diag SPEC` | Diagnose (`dns://…`, `ping://…`, …) |
| `capture IFACE` | Live capture |
| `open PATH` | Open pcap/pcapng |
| `mock` | Mock on `tcp://127.0.0.1:18080` |
| `mock tcp://…` | Mock on bind URI |
| `import PATH` | Import Postman / OpenAPI |
| `codegen NAME [curl\|rust]` | Generate under `./bitbeak-out/` |
| `run NAME` | Run request from loaded collection |
| `env NAME` | Set collection environment |
| `geoip-status` | GeoIP database status |
| `rpcap host[:port]` | Probe rpcap |
| `rpcap host[:port] iface` | Live rpcap capture |

## HTTP session

| Command | Action |
| --- | --- |
| `auth` | Cycle auth kind |
| `oauth` | Start OAuth2 browser + loopback (Auth=OAuth2) |
| `body-mode` | Cycle raw / urlencoded / multipart / GraphQL |
| `http-version` | Cycle Auto / HTTP/1 / HTTP/2 |
| `grpc` | Toggle unary gRPC mode |
| `grpc-desc PATH` | Protobuf descriptor set path |
| `grpc-type TYPE` | Protobuf message type |
| `gql-introspect` | Load GraphQL introspection query |
| `pre-script …` | Set Rhai pre-request script |
| `history` | Focus history pane |
| `cookies on` / `cookies off` | Cookie jar |

## Capture session

| Command | Action |
| --- | --- |
| `follow-tcp` / `follow-udp` / `follow-http` | Follow selected stream |
| `replay-http` | Follow HTTP stream |
| `conversations` / `endpoints` / `hierarchy` / `expert` | Analysis overlays |
| `keylog` | Keylog status overlay |
| `inject` | Inject selected frame |
| `composer` | Capture composer |
| `cfilter …` | Set capture filter |
| `export-objects` | Export HTTP objects (after `follow-http`) |
| `names-toggle` | Toggle name resolution |
| `manuf-reload` / `manuf-status` | Manuf / OUI database |

## Related docs

- [HTTP](http.md) · [Capture](capture.md) · [Collections](collections.md) · [Sessions](sessions.md)
