---
layout: default
title: HTTP / GraphQL / gRPC
---

# HTTP / GraphQL / gRPC

[Docs home](index.md)

HTTP sessions send real requests over HTTP/1.1 or HTTP/2 (ALPN). Open with a `http://` / `https://` URI, **F2 → HTTP**, or `:` `http …`.

## Request pane

Fields: Method, URL, Auth, Headers, Body (or form / GraphQL editors).

- **Enter** on Method / URL / Headers sends the request
- In Body (and most auth text fields): **Enter** = newline, **Ctrl+Enter** = send
- Timing waterfall + TLS summary appear in the response pane when available
- Redirects can be followed (client setting); hops show in the summary

## Auth (`:` `auth`)

Cycles: None → Bearer → Basic → API key (header) → API key (query) → OAuth2.

| Kind | Fields |
| --- | --- |
| Bearer | Token |
| Basic | Username / password |
| API key | Name + value (header or query) |
| OAuth2 | User=`client_id`, Pass=`client_secret`, Key=`auth_url`, Value=`token_url`, Token=access |

Run `:` `oauth` with Auth kind OAuth2 to open the browser + loopback exchange. Tokens may be stored under `~/.config/bitbeak/oauth.toml` (mode `0600`).

## Body modes (`:` `body-mode`)

Raw → urlencoded → multipart → GraphQL → …

- **Urlencoded / multipart:** form key/value(/file) editor; **a** / **d** add/delete rows
- **GraphQL:** query, variables (JSON), operation name
- `:` `gql-introspect` loads a standard introspection query into the GraphQL body

## HTTP version (`:` `http-version`)

Cycles Auto / HTTP/1 / HTTP/2 for the client connector.

## Unary gRPC

1. `:` `grpc` — toggle gRPC mode (forces POST)
2. Optional JSON↔protobuf via descriptors:
   - `:` `grpc-desc /path/to/descriptor.pb` (or FileDescriptorSet)
   - `:` `grpc-type package.MessageType`
3. Without descriptor + type, the body is sent as raw protobuf bytes in a gRPC frame

Reply type defaults by renaming `FooRequest` → `FooResponse` when decoding JSON responses.

## Pre-request scripts

```text
: pre-script req.url = req.url + "v1";
```

Rhai script with `req.url`, `req.body`, and collection `env` bindings. Set on the active HTTP session.

## Cookies & history

- `:` `cookies on` / `cookies off` — jar under `~/.config/bitbeak/cookies.toml`
- History pane (**F**ocus with `:` `history`); **Enter** replays the selected entry
- **F7** runs a short sequential bench on the current HTTP request

## Collections

Save/load requests via **F9**. See [Collections](collections.md).

## Related palette commands

See [Command palette](palette.md) for `auth`, `body-mode`, `http-version`, `grpc*`, `gql-introspect`, `pre-script`, `history`, `oauth`.
