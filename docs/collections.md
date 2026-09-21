---
layout: default
title: Collections
---

# Collections

[Docs home](index.md)

Collections store named HTTP requests and environments under the BitBeak config directory.

## Config directory

Default root: `~/.config/bitbeak/`

| Path | Purpose |
| --- | --- |
| `collections/` | Saved collection JSON |
| `cookies.toml` | Cookie jar |
| `history/` | HTTP history entries |
| `oauth.toml` | OAuth tokens (mode `0600`) |
| `ca/ca.pem` | Local-debug TLS intercept CA (install in client) |
| `manuf` | Optional OUI database |
| `GeoLite2-City.mmdb` | Optional MaxMind GeoIP |
| `export/` | HTTP object export from capture |

## TUI

- **F9** — browse collections / requests
- Enter opens a collection; Enter on a request loads it into an HTTP session
- Tab / `e` cycles environment when viewing requests
- Save from an HTTP session with the collections UI (see in-app hints)

Palette:

| Command | Action |
| --- | --- |
| `:` `run NAME` | Load named request from the active collection |
| `:` `env NAME` | Switch active environment |
| `:` `import PATH` | Import Postman v2.1 or OpenAPI 3 and save |
| `:` `codegen NAME [curl\|rust]` | Write `./bitbeak-out/` scripts |

## CLI

```bash
bitbeak --collection my-api
bitbeak --collection my-api https://api.example.com/v1/orders/123
bitbeak --import ./collection.postman_collection.json
bitbeak --codegen demo --codegen-lang curl
```

`--import` and `--codegen` exit after completing (no TUI).

With `--collection` and an HTTP URL, BitBeak opens that request and fills method, headers, auth, body, and tests from the best matching saved request. `--collection` alone opens the first saved request.

## Import

**Postman Collection v2.1** maps:

- Collection `variable` → a `collection` environment (so `{{baseUrl}}` works)
- Request / folder `auth` → Bearer, Basic, or API key
- Body modes `raw`, `urlencoded`, `formdata`, `graphql`
- `event` prerequest `exec` → `pre_script`

**OpenAPI 3** maps path operations, example bodies (one-level `$ref`), query parameters without examples as `{{name}}`, and `securitySchemes` / `security` onto auth.

## Environments

Collections support named environments and `{{var}}` substitution in requests when building the HTTP spec. Switch with `:` `env …` or the collections overlay.

## Codegen

`codegen` emits:

- **curl** — shell script under `./bitbeak-out/` (includes `-u`, `Authorization`, and API-key headers/query when auth is set)
- **rust** — reqwest-oriented client stub under `./bitbeak-out/` (bearer / basic / API key)

Generated files include an AGPL header comment.
