# Protocol design notes

**Status: DRAFT.** Candidate directions and constraints for the obscura
protocol. Nothing here is final; the handshake in particular must not be
implemented until the threat model has been reviewed.

## 1. Hard constraints

1. **No invented cryptography.** No new primitives, no new combiners, no
   hand-rolled padding schemes. The protocol is an *assembly* of
   well-analyzed parts, ideally following an existing framework so that
   analysis transfers.
2. **Fail closed.** Any violation (bad MAC, bad framing, bad state transition)
   aborts the session. No optional leniency modes.
3. **Every byte on the wire is versioned and length-bounded.**
4. **The core must be implementable without a heap eventually** (`no_std`
   friendly structures: fixed-capacity buffers, explicit bounds).

## 2. Candidate building blocks

| Role | Candidates | Notes |
| --- | --- | --- |
| Handshake / key exchange | **Noise Protocol Framework** patterns (`XX`, `IK`, `XXpsk`) | Gives analyzed forward-secret handshakes, identity hiding options, and a formal-ish treatment for free. Strongly preferred over designing a bespoke handshake. |
| AEAD | ChaCha20-Poly1305 (RFC 8439), AES-256-GCM (hardware AES-NI paths) | Pick one mandatory-to-implement + one accelerated. Nonce strategy: sequence-number-derived, per RFC 8439 §4 style construction. |
| DH / KEM | X25519 (RFC 7748) | PQ hybridization is an extension point, not v1. |
| KDF | HKDF-SHA-256 (RFC 5869), BLAKE3 as alternative | Noise already specifies HKDF usage; follow it rather than improvising. |
| RNG boundary | OS entropy only (`getrandom`) | Keys never derived from user-space randomness. |

## 3. Record layer

The first implemented layer is message framing
(`src/frame.rs`): a 4-byte big-endian length prefix followed by opaque
payload bytes, with a hard maximum frame length enforced before any
allocation.

Planned evolution into the record layer:

```
record = length_prefix || ciphertext || tag
```

with the plaintext carrying a content type and epoch so that rekeying and
future message kinds can be multiplexed without parsing plaintext early.
Details deliberately unspecified until G2/G5 review (see THREAT_MODEL.md).

## 4. Versioning and extensibility

- Handshake carries a `protocol_version` field and an extension list;
  unknown extensions are ignored by the responder unless flagged required.
- No "downgrade to plaintext" mode will ever exist.

## 5. Testing strategy

- Property tests for framing (arbitrary chunk splits, truncations, hostile
  lengths).
- Fixed test vectors for every crypto-bearing layer, cross-checked against a
  second independent implementation where possible.
- Interop fixtures committed under `vectors/` once the handshake exists.

## 6. References

- Noise Protocol Framework — https://noiseprotocol.org/noise.html
- RFC 8439 — ChaCha20-Poly1305 AEAD
- RFC 7748 — X25519/X448
- RFC 5869 — HKDF
- RFC 8446 — TLS 1.3 (prior art for record layer and fail-closed rules)
