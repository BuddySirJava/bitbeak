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
| `mocks/` | Mock route TOML per bind |
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
bitbeak --import ./collection.postman_collection.json
bitbeak --codegen demo --codegen-lang curl
bitbeak --codegen demo --codegen-lang rust
```

`--import` and `--codegen` exit after completing (no TUI).

## Environments

Collections support named environments and `{{var}}` substitution in requests when building the HTTP spec. Switch with `:` `env …` or the collections overlay.

## Codegen

`codegen` emits:

- **curl** — shell script under `./bitbeak-out/`
- **rust** — reqwest-oriented client stub under `./bitbeak-out/`

Generated files include an AGPL header comment.
