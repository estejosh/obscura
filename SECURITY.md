# Security policy

## Supported versions

The project is pre-alpha: only the latest commit on `main` is considered.
No released version receives security maintenance yet.

## Reporting a vulnerability

**Do not open a public issue for anything you believe is security-relevant.**

Report privately via GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
for this repository (Repository → Security → Report a vulnerability). If you
cannot use that channel, contact the maintainer directly to arrange one.

Include, where possible:

- Affected code path or protocol layer (framing, future handshake, …).
- Steps or proof-of-concept to reproduce.
- Impact assessment and any suggested mitigation.

You will receive an acknowledgment; please allow reasonable time for a fix
before any public disclosure.

## Scope notes

- The protocol itself is still being designed — conceptual protocol flaws are
  best raised as ordinary issues or discussions against `DESIGN.md` /
  `THREAT_MODEL.md` unless they affect already-implemented code.
- Out of scope: endpoint compromise, side channels of the host platform, and
  denial of service by bandwidth exhaustion at layers above the transport.
