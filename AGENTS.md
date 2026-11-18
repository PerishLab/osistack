# Agent guide

Read the canonical [PerishLab delivery governance](https://github.com/PerishLab/.github/blob/main/GOVERNANCE.md)
at work start and again before delivery or Issue closure. That document owns
organization-wide Issue, pull-request and acceptance policy; this file keeps
repository-specific constraints without copying that policy.

Osistack is a network stack in the spirit of the OSI layers, each layer
implemented, observed and replaceable on its own. Its first target is the widely
used subset of HTTP/1.1, HTTP/2 and HTTP/3 over a self-built TLS and a
self-built QUIC, meant to replace request libraries and curl across the
PerishLab domain over time.

## Contract

Issue #3 is the contract. The approved decisions, the v0 subset with its
exclusions, the milestones and the verification ladder live there and nowhere
else; this file does not copy them. A change to any of them is recorded with its
reason in an Issue.

## Boundaries

- Dependencies run from the composition crate toward the protocol crates. No
  crate performs I/O and every protocol core is sans-I/O.
- At most 10 crates, each with one responsibility, and never `utils` or `shared`.
  `wire` holds only binary primitives that more than one protocol shares and is
  not a toolbox.
- `osistack` (`crates/lib`) is the Plumb anchor crate and the only one that
  wires the others together.
- Seams are traits and data. `quic` defines a handshake provider that `tls`
  implements, and `h3` defines a transport that `quic` implements. The TLS
  handshake engine stays apart from the record layer because QUIC uses only the
  handshake (RFC 9001).
- A third-party dependency needs a real consumer, and a public build must be able
  to reach and license it.
- The capability profile in `osistack` is the only statement of what is
  supported, excluded and unverified. Keep it equal to the code, and never state
  a capability that no test proves.

## Verification

Use focused tests while developing and the complete applicable Guard at
coherent delivery boundaries. Inline RFC vectors and, once the simulator exists,
deterministic simulation gate a leaf. External suites, Wycheproof and fuzzing,
and smoke checks against public endpoints do not gate until an explicit Issue
promotes one after it has produced a stable baseline. Consumer parity lives in
the consumer's repository and never blocks acceptance here.

A level that has not run is stated as not run and never reported as run, and
passing one level never implies the levels above it. A test corpus is read from
a path supplied through the environment, never embedded, and its license is
registered in `CREDITS.md` first.

## Consumers and credit

Credential-carrying consumers (hardrig, santi, ensign) are not replaced before
the condition in #3 decision D7 holds. Anything borrowed from another
implementation is registered in `CREDITS.md` in the same change that introduces
it, under the rules written there.
