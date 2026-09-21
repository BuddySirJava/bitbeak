---
layout: default
title: HTTP / GraphQL / gRPC
---

# HTTP / GraphQL / gRPC

[Docs home](index.md)

HTTP sessions send real requests over HTTP/1.1 or HTTP/2 (ALPN). Open with a `http://` / `https://` URI, **F2 → HTTP**, or `:` `http …`. A CLI URL pre-fills **GET** and that URL; `--collection NAME` also loads matching method, headers, auth, and tests.

## Request pane

Fields: Method, URL, Auth, Headers, Body (or form / GraphQL editors).

- **Enter** on Method / URL / Headers sends the request
- In Body (and most auth text fields): **Enter** = newline, **Ctrl+Enter** = send
- Timing waterfall (DNS, TCP, TLS handshake, TTFB) is measured on the **same** connection used for the request
- Redirects follow curl-like rules: **301 / 302 / 303** become **GET** with an empty body; **307 / 308** keep method and body. Hops show in the summary

## Auth (`:` `auth`)

Cycles: None → Bearer → Basic → API key (header) → API key (query) → OAuth2.

| Kind | Fields |
| --- | --- |
| Bearer | Token |
| Basic | Username / password |
| API key | Name + value (header or query) |
| OAuth2 | User=`client_id`, Pass=`client_secret`, Key=`auth_url`, Value=`token_url`, Token=access |

Run `:` `oauth` with Auth kind OAuth2 to open the browser + loopback exchange with **PKCE (S256)**. If a refresh token is already stored, BitBeak tries refresh first. Tokens live under `~/.config/bitbeak/oauth.toml` (mode `0600`).

## Body modes (`:` `body-mode`)

Raw → urlencoded → multipart → GraphQL → …

- **Urlencoded / multipart:** form key/value(/file) editor; **Ctrl+N** add / **Ctrl+X** delete rows (plain `a`/`d` type into the field)
- **GraphQL:** query, variables (JSON), operation name
- `:` `gql-introspect` loads a standard introspection query into the GraphQL body

## HTTP version (`:` `http-version`)

Cycles Auto / HTTP/1 / HTTP/2 for the client connector.

## Pre-request scripts

```text
: pre-script req.url = req.url + "v1"; req.headers["X-Trace"] = "1";
: pre-script-show          # multi-line editor (Ctrl+Enter save)
: pre-script-clear
```

Rhai script with `req.url`, `req.method`, `req.body`, `req.headers` (map), and collection `env` bindings. Status shows `script:on` when set.

## Response tests (asserts)

```text
: test status == 200
: test header Content-Type contains json
: test body contains ok
: test jsonpath $.id exists
: tests                    # multi-line editor
: test-clear
```

Expressions run after each successful HTTP or gRPC response. Status badge `tests:N`. Postman `test` events import status/body checks when possible.

## Unary gRPC

1. `:` `grpc` — toggle gRPC mode (forces POST)
2. Optional JSON↔protobuf via descriptors:
   - `:` `grpc-desc /path/to/descriptor.pb` (or FileDescriptorSet)
   - `:` `grpc-type package.MessageType`
   - `:` `grpc-reply package.ReplyType` (optional; else `FooRequest` → `FooResponse`)
3. Session headers and auth are forwarded; `:authority` is taken from the URL host
4. Compressed gRPC frames are rejected with a clear error

`grpc-status` / `grpc-message` are read from **trailers** (falling back to headers).

## Cookies & history

- `:` `cookies on` / `cookies off` — jar under `~/.config/bitbeak/cookies.toml`
- Parses `Secure`, `Max-Age` / `Expires`; **Secure** cookies are not sent on `http://`
- History pane (`:` `history`); **Enter** replays the selected entry
- **F7** runs a short sequential bench on the current HTTP request

## Collections

**F9**: Enter loads; `s` overwrites selected (or appends if empty); **Shift+S** appends; `d` deletes. See [Collections](collections.md).

## Related palette commands

See [Command palette](palette.md) for `auth`, `body-mode`, `http-version`, `grpc*`, `gql-introspect`, `pre-script`, `test*`, `history`, `oauth`, `sniff`.
