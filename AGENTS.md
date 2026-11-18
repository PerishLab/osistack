# Osistack

Read the canonical [PerishLab delivery governance](https://github.com/PerishLab/.github/blob/main/GOVERNANCE.md)
at work start and again before delivery or Issue closure.

Osistack is a network stack built in the spirit of the OSI layers, with each
layer implemented, observed and replaceable on its own. Its first target is the
widely used subset of HTTP/1.1, HTTP/2 and HTTP/3, carried by a self-built TLS
and a self-built QUIC, meant to replace request libraries and curl across the
PerishLab domain over time.

Mature designs and best practices may be followed openly, and every such
source is credited by name. Keep supported subsets, deliberate exclusions and
unverified behavior distinct.

This workspace has no network runtime, protocol implementation or release yet.
It holds the contract below and three crates that establish its first real
source. A compiling interface, a profile entry or a refusal of an unavailable
operation never proves protocol behavior. The contract is Issue #3; the source
boundary that establishes it is Issue #4.

## Approved decisions

The user approved these on 2026-11-17. A later change is recorded with its
reason in an Issue, never drifted silently.

- D1: Protocols are self-built. Cryptographic primitives first come from
  existing implementations behind a `crypto` seam and are replaced one at a
  time. Each replacement passes RFC vectors, Wycheproof and differential tests
  against the existing implementation.
- D2: TLS 1.3 only. TLS 1.2 waits until the domain's endpoint inventory proves
  a need.
- D3: A synchronous client comes first and every protocol core is sans-I/O. No
  replacement of hyper or axum servers.
- D4: The v0 subset below. The curl replacement is M5 and is modeled later from
  observed flags.
- D5: Only `osistack`, `http` and `wire` exist in M0. Other crates arrive with
  the first leaf of their line, and the total never exceeds 10.
- D6: A leaf is accepted by inline RFC vectors plus deterministic simulation.
  External suites (h2spec, openssl differential, Interop Runner, BoGo, h3spec)
  first produce non-gating baselines. Seatrial scenes are built before the
  milestone that needs them.
- D7: Until the self-built TLS passes its baseline and the user approves, no
  credential-carrying consumer (hardrig, santi, ensign) is replaced. Loopback or
  credential-free traffic comes first.
- D8: Linux x86_64 GNU ships first and core code stays platform independent.
  macOS and Windows each get an independent Feature from day zero, outside the
  required leaves. The v0 trust root is an explicit PEM file only.
- D9: Attribution lives in `CREDITS.md` at the repository root, never in source
  comments. Only MIT, Apache, ISC, BSD and curl licensed sources are borrowed;
  GPL tlsfuzzer is an external tool only. This is an engineering judgment, not
  legal advice. Any borrowing, whatever its level, is registered in `CREDITS.md`
  in the same change that introduces it.
- D10: One osistack Project plans the work. After M0 two lines run in parallel
  as a pilot; measured data decides any widening. Total effort is the user's
  to set.

## Ownership

Dependencies run from the composition crate toward the contract crates, and
`http` and `wire` depend on nothing in this workspace. No crate performs I/O.
Third-party dependencies need a real consumer, and a public build must be able
to reach and license them.

- `osistack` (`crates/lib`) is the anchor and public entry. It re-exports
  `http` and `wire`, publishes the capability profile (supported, excluded,
  unverified) and refuses operations that are not available.
- `http` owns protocol-independent semantic types: method, status, field name
  and field value, with validation and rejection. It has no wire encoding.
- `wire` owns binary primitives: the byte reader and writer, the QUIC
  variable-length integer of RFC 9000 section 16, and the prefix integer of
  RFC 7541 section 5.1 with a 1 to 8 bit prefix, shared by HPACK and QPACK. The
  varint decoder accepts a longer-than-necessary encoding because RFC 9000
  permits it (a Frame Type field is the exception and its owner checks the
  length) and the encoder always writes the shortest. The prefix decoder accepts
  zero-padded continuation bytes and refuses any value above `u64::MAX`. Huffman
  coding is not delivered yet. `wire` is not a toolbox and takes no unrelated
  helper.

Candidate crates, at most 10 in total: `osistack`, `cli`, `http`, `h1`, `h2`
(with HPACK), `h3` (with QPACK), `tls` (with X.509), `quic`, `crypto`, `wire`.
There is no `utils` or `shared`. Seams are traits and data: `quic` defines a
handshake provider that `tls` implements, `h3` defines a transport that `quic`
implements, and `osistack` wires them. The TLS handshake engine stays separate
from the record layer because QUIC uses only the handshake (RFC 9001).

## v0 subset

- HTTP/1.1 client: message framing, Content-Length, chunked, keep-alive pool,
  `Connection: close`, tolerated HTTP/1.0 responses, request smuggling defense,
  redirect policy including no-follow, total and phased timeouts, and status
  codes that are not errors. Excluded: pipelining, Upgrade and WebSocket,
  trailers, `Expect: 100-continue`, cookies, compression, authentication
  schemes. Proxies are unobserved. The server is a minimal loopback test server
  only.
- TLS 1.3 client: X25519 and P-256, AES-GCM and ChaCha20-Poly1305, ECDSA and RSA
  signature verification, SNI, ALPN, chain and host name validation, explicit
  PEM roots. Excluded: TLS 1.2, resumption and 0-RTT, client certificates,
  revocation. A TLS server exists only for tests.
- HTTP/2 client: SETTINGS, HEADERS and CONTINUATION, DATA, WINDOW_UPDATE flow
  control, RST_STREAM, GOAWAY, PING, complete HPACK, concurrent streams,
  connection reuse, `SETTINGS_ENABLE_PUSH=0`. Excluded: server push, the legacy
  priority tree, h2c upgrade (prior knowledge in tests only), extended CONNECT.
- QUIC v1: RFC 9000 handshake with Retry, version negotiation, stream and
  connection flow control, connection IDs, path validation, key update, RFC 9002
  NewReno. Excluded: CUBIC and BBR, migration beyond NAT rebinding, 0-RTT,
  DATAGRAM, multipath. ECN and GSO are unobserved.
- HTTP/3 client: control stream and SETTINGS, HEADERS and DATA, QPACK with the
  static and dynamic tables and blocked streams, GOAWAY, Alt-Svc discovery in
  the client. Excluded: push and WebTransport.
- Also excluded: user-space TCP/IP, replacing hyper or axum servers, replacing
  the curl in Guard or CI bootstrap (it would form a bootstrap loop), chasing
  HTTP/3 for consumers without a proven need, hardware accelerated primitives on
  day one, and full curl parity.

## Milestones

M0 is the contract and these three crates, then attribution (O-2) and the
verification ladder (O-3). M1 is the HTTP/1.1 plaintext client with a loopback
server and a synchronous client. M2 is the TLS 1.3 client, X.509 and HTTP/1.1
over TLS. M3 is HTTP/2 over TLS. M4 is QUIC v1 and HTTP/3. M5 is the minimal
server, the curl subset command line and TLS 1.2 on demand. Each line is
modeled as leaves when its turn comes; ordering uses native blocked-by
relations only.

## Verification

Use focused tests while developing and the complete applicable Guard at
coherent delivery boundaries. The ladder below says what each level proves, who
runs it and whether it gates. A level that does not exist yet is stated as such
and never reported as run.

| Level | What it proves | Who runs it | Gate |
|---|---|---|---|
| V0 | Inline RFC vectors and rejected malformed input per leaf | Guard, in the leaf's tests | Yes. Delivered now for `wire` (RFC 9000 appendix A.1, RFC 7541 appendix C.1) |
| V1 | Deterministic simulation with virtual time, loss and reordering | Guard | Yes, once it exists. The simulator arrives with the first leaf of the QUIC line, after M1. This repository has none |
| V2 | External differential and conformance suites: openssl, nghttpd, h2spec, h3spec, a BoGo shim, Interop Runner | The machine or a Windtun scene | No at first. None has been run and no baseline exists |
| V3 | Wycheproof vectors and fuzzing | Machine or Guard | No at first. No corpus exists |
| V4 | Read-only smoke checks against public endpoints | The machine | No. None has been run |
| V5 | Consumer parity | The consumer's own repository | Never blocks osistack acceptance |

An external suite is promoted into a gate only by an explicit Issue after it has
produced a stable baseline. Passing a level never implies the levels above it.

### Writing a vector test

`crates/wire/tests/rfc9000.rs` and `crates/wire/tests/rfc7541.rs` are the
models for later lines. Each file is named for the RFC it quotes and each test
for the section or example it pins. Write the bytes and the expected value as
literals next to one another, assert the decoding and the encoding, and include
at least one malformed input that must be refused. A vector comes from the RFC
text and is checked against it when added; where an RFC permits more than one
encoding, the test records which one the code decodes and which one it writes.

### Source constraints

Source here follows Ectropy, with these limits verified against its checks:

- No source comments. Reasoning lives in this file and in Issues.
- Names are single words, so function and test names are single words. A
  compound or protocol term needs a registered `[[vocabulary.term]]` entry with a
  one-line description in `ectropy.toml`. None is registered yet.
- A function takes at most four parameters, a tuple has at most three positions
  and a boolean expression at most three atoms. A named type carries more.
- Dispatch uses `match`, not a chain of `if x == literal`.
- A directory holds at most ten entries and paths are at most three levels deep.
- Tests state expectations as literals. They never use `CARGO_MANIFEST_DIR` and
  never embed a repository file.

There is no external corpus yet. When one is needed, its tests read it from a
path supplied through the environment, which the test environment grant in
`ectropy.toml` allows, and never embed it in source. Its license is registered
in `CREDITS.md` first.

`wire` tests pin the RFC examples and the rejection of truncated and
overflowing input; `http` tests pin the rejection of malformed tokens, field
values and status codes; `osistack` tests pin the profile against the v0 subset
and the refusal of Fetch and Serve.

Nothing here claims a protocol, TLS, QUIC or cryptographic capability, a
release, an installation or a platform qualification. No external suite baseline
has been produced. Unknown scope is not counted as passing.
