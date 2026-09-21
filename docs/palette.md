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
| `proxy bind|upstream [--tls-intercept]` | Open TCP proxy; optional MITM (HTTP/1.1) |
| `ca-path` | Flash BitBeak MITM CA PEM path |
| `diag SPEC` | Diagnose (`dns://…`, `ping://…`, …) |
| `capture IFACE` | Live capture |
| `open PATH` | Open pcap/pcapng |
| `import PATH` | Import Postman / OpenAPI |
| `codegen NAME [curl\|rust]` | Generate under `./bitbeak-out/` |
| `run NAME` | Run request from loaded collection |
| `env NAME` | Set collection environment |
| `geoip-status` | GeoIP database status |
| `rpcap host[:port]` | Probe rpcap (**experimental**) |
| `rpcap host[:port] iface` | Live rpcap capture (**experimental**) |
| `fuzz` | Open fuzz overlay (same as **F11**) |

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
| `grpc-reply TYPE` | Protobuf reply message type |
| `gql-introspect` | Load GraphQL introspection query |
| `pre-script …` / `pre-script-show` / `pre-script-clear` | Rhai pre-request script |
| `test EXPR` / `tests` / `test-clear` | Response asserts |
| `history` | Focus history pane |
| `cookies on` / `cookies off` | Cookie jar |
| `sniff` / `capture-http [iface]` | Capture traffic for this URL host |

## Capture session

| Command | Action |
| --- | --- |
| `follow-tcp` / `follow-udp` / `follow-http` | Follow selected stream |
| `replay-http` | Follow HTTP (if needed) and load first request into an HTTP tab |
| `sniff` / `capture-http [iface]` | From HTTP tab: open capture, filter on URL host, start sniffing |
| `conversations` / `endpoints` / `hierarchy` / `expert` | Analysis overlays |
| `keylog` / `keylog PATH` | Keylog status overlay / load NSS keylog and redigest |
| `save [path]` / `save-all` | Save displayed (or all) packets; F12 uses default path |
| `inject` | Inject selected frame |
| `composer` | Open stream composer targeted at selected packet peer |
| `cfilter …` | Set capture filter |
| `export-objects` | Export HTTP objects (after `follow-http`) |
| `names-toggle` | Toggle name resolution |
| `manuf-reload` / `manuf-status` | Manuf / OUI database |

## Related docs

- [HTTP](http.md) · [Capture](capture.md) · [Collections](collections.md) · [Sessions](sessions.md)
