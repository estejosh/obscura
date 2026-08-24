# Contributing

Thanks for helping build obscura. This is a security-focused project, so a
few rules are strict.

## Ground rules

1. **No novel cryptography.** Changes must assemble well-analyzed building
   blocks. Proposals for new primitives or bespoke handshakes will be
   declined — see `DESIGN.md`.
2. **Fail closed.** Error paths abort sessions; no leniency or fallback
   modes.
3. **`unsafe` is forbidden** (enforced by `#![forbid(unsafe_code)]`). If you
   genuinely need it, open an issue first.
4. **Tests required.** Every behaviour change ships with tests, including
   hostile-input cases.

## Development

Requires a stable Rust toolchain (edition 2024).

```sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

CI runs all four on every PR; please run them locally first. Keep the diff
minimal and focused — one logical change per pull request.

## Design changes

Protocol and threat-model changes start as an issue describing the problem,
referencing the relevant goals/open questions in `THREAT_MODEL.md`. Substantive
design discussion happens before any implementation lands.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) — never open public issues for suspected
vulnerabilities.
