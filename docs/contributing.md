---
layout: default
title: Contributing
---

# Contributing

[Docs home](index.md)

## Development checks

These match CI (`.github/workflows/ci.yml`):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

On Linux, install build deps for `aws-lc-rs` if needed: `cmake`, `clang`, `pkg-config`.

Optional license/advisory gate: `cargo deny` (see `deny.toml`).

## Documentation site (GitHub Pages)

Docs live in `/docs` (this folder). After the first push to GitHub:

1. Repo **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: `master` (or `main`), folder: **`/docs`**

The public URL will be `https://bitbeak.github.io/bitbeak/` (org/user pages naming may differ if the repo moves).

No extra Actions workflow is required for plain Jekyll `/docs` publishing with `_config.yml`.

## License

BitBeak is **GNU Affero GPL v3 or later**. Contributions are expected under the same terms. See [LICENSE](https://github.com/bitbeak/bitbeak/blob/master/LICENSE).
