# Threat model

**Status: DRAFT.** This document frames the security discussion for obscura.
It is a starting point for review, not a finished analysis.

## 1. System under discussion

Two endpoints (clients, servers, or peers) exchange messages over an untrusted
network (the internet, a LAN, or any packet-bearing medium). Obscura provides
an encrypted, authenticated transport channel between them. The protocol is
platform agnostic; endpoints may have very different capabilities.

## 2. Assets to protect

- **A1 — Message confidentiality**: content of in-flight messages.
- **A2 — Message integrity**: undetected modification, injection, reordering,
  replay, truncation, or reflection of messages.
- **A3 — Peer identity**: assurance that the peer is who the local endpoint
  intended to talk to.
- **A4 — Session keys**: long-term secrecy of past sessions even if long-term
  identity keys are later compromised (forward secrecy).

## 3. Adversaries and capabilities

| Adversary | Capabilities | In scope |
| --- | --- | --- |
| Passive eavesdropper | Reads all traffic, cannot modify | Yes |
| Active network attacker | Full MITM: read, drop, reorder, replay, inject, terminate | Yes |
| Malicious endpoint | Compromised or dishonest peer | Partially: after authentication, a valid peer can do whatever the application allows. Protocol protects only channel properties. |
| Endpoint attacker | Reads memory, keys, or code of one endpoint | No (endpoint compromise is out of scope) |
| Traffic analyst | Observes timing, sizes, counts | Explicit non-goal for v1; framing must not leak *content*, but padding/cover traffic is not planned |

## 4. Security goals

The protocol MUST provide, per session:

- **G1** Confidentiality of message contents against passive and active
  network attackers (A1).
- **G2** Integrity and authenticity of every record: no undetectable
  modification, splicing, reflection, reordering, or replay within a session
  (A2).
- **G3** Peer authentication, at minimum against active impersonation during
  handshake. Whether authentication is mutual-by-default or optional modes
  exist is an open question ([Q3](#8-open-questions)).
- **G4** Forward secrecy: compromise of long-term keys does not reveal past
  session traffic (A4).
- **G5** Fail-closed behaviour: any framing, decryption, or MAC failure tears
  down the session immediately; no error-triggered fallback paths.

## 5. Non-goals

- Anonymity, IP hiding, or metadata protection.
- Deniability of participation (may be revisited; handshake pattern choice
  affects it — see [DESIGN.md](DESIGN.md)).
- DoS resistance beyond cheap rejection of malformed input (e.g. bounded
  frame lengths before allocation).
- Post-quantum security in v1 (tracked as an extension point).
- Protecting an endpoint from itself (bad RNG, compromised OS, side channels).

## 6. Trust assumptions

- Endpoints can generate or obtain cryptographically strong random values for
  key material (`OsRng` or platform equivalent). The protocol fails if this
  assumption breaks.
- At least one accepted mechanism exists to authenticate identity keys
  (TOFU, pre-shared list, certificates, or user verification) — the *binding*
  mechanism is application-level and out of protocol scope, but the protocol
  must expose stable identity-key handles for it.
- Underlying transport delivers arbitrary-length byte streams or datagrams;
  obscura's own framing layer is responsible for record boundaries.

## 7. Attack surfaces in the implementation

- Framing decoder: hostile length prefixes must never cause large allocations
  (enforced maximum, checked *before* reserving capacity).
- Handshake state machine: out-of-order or repeated handshake messages must be
  rejected, not buffered unboundedly.
- Crypto library boundaries: only vetted, maintained crates; versions pinned;
  no hand-rolled primitives.

## 8. Open questions

- **Q1**: Transport model — stream-oriented (TCP-like), datagram-oriented
  (UDP-like), or both? Affects record layer design and replay windows.
- **Q2**: Is a plaintext protocol-version negotiation round needed, or is
  version fixed at v1 with future negotiation via extension fields?
- **Q3**: Authentication topology — mutual-only, server-only, or pattern
  parameterised (cf. Noise `XX`, `IK`, `XXpsk`)?
- **Q4**: Rekey policy (bytes/time-based) and what forward secrecy means
  across rekeys.
- **Q5**: Embedded constraints — `no_std` support level, heap usage budget.
