# obscura

safe secure transport protocol for communications, platform agnostic

## Status

**Pre-alpha / design phase.** The protocol is not yet specified and nothing here
is secure or stable. Do not use for anything real. The repository currently
contains design documents and a small, well-tested framing scaffold — see the
[roadmap](#roadmap).

## Goals

- **Secure by construction**: confidentiality, integrity, replay protection,
  and forward secrecy over an untrusted network.
- **Platform agnostic**: one core protocol that runs everywhere — desktop,
  server, mobile, and (eventually) embedded — with thin platform adapters.
- **Simple to review**: a security project must be auditable. Small surface,
  boring choices, extensive tests.

## Non-goals (v1)

- Anonymity or metadata hiding.
- Post-quantum key exchange (tracked as a future extension; see
  [DESIGN.md](DESIGN.md) open questions).
- General-purpose RPC/stream multiplexing on top of the channel.

## Design principles

1. **No novel cryptography.** Only well-analyzed constructions and patterns
   (e.g. Noise-framework handshakes, AEAD ciphers, X25519, HKDF). Any new
   primitive is out of bounds; see [DESIGN.md](DESIGN.md) and
   [THREAT_MODEL.md](THREAT_MODEL.md).
2. **Memory-safe implementation language.** The reference implementation is
   Rust; `unsafe` is disallowed outside reviewed, justified exceptions.
3. **Fail closed.** Any protocol violation tears down the session.
4. **Test everything.** Every layer carries unit tests; interop will be pinned
   by test vectors once the protocol is specified.

## Repository layout

| Path             | Contents                                            |
| ---------------- | --------------------------------------------------- |
| `DESIGN.md`      | Protocol design notes and candidate building blocks |
| `THREAT_MODEL.md` | Threat model (draft)                               |
| `src/`           | Rust crate: shared framing layer (first building block) |

## Development

Requires a stable Rust toolchain (edition 2024).

```sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Security

Please report vulnerabilities privately — do not open a public issue. See
[SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

obscura is licensed under the **Business Source License 1.1** (`BUSL-1.1`) —
source-available and fully auditable, but *not* open source (yet). In brief:

- **Free**: read/audit the source, internal use, evaluation, non-production
  use; redistribution of unmodified copies under the same license.
- **Seat license required**: production use and commercial use — contact
  estejosh for a written seat license.
- **Not allowed**: distributing derivative works; provisioning a competing
  protocol service from this code.
- **Change Date 2030-08-23**: each version converts to Apache-2.0.

Full terms: [LICENSE.md](LICENSE.md) · plain-language summary:
[LICENSE-PARAMETERS.md](LICENSE-PARAMETERS.md).

## Roadmap

- [x] Project charter: goals, non-goals, principles
- [ ] Threat model review
- [ ] Protocol specification draft (handshake, record layer)
- [ ] Framing layer (`src/frame.rs`) — done, under review
- [ ] Handshake implementation on an established pattern (e.g. Noise)
- [ ] Encrypted transport channels + integration tests
- [ ] Interop test vectors and cross-platform CI matrix
- [ ] `0.1` release with chosen license and security policy
