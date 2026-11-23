# Credits

This is osistack's attribution registry. Attribution lives here and never in
source comments (decision D9 of the cold-start contract, Issue #3). The rules
below are an engineering judgment, not legal advice.

## Borrowing rules

- Only sources under MIT, Apache-2.0, ISC or BSD-family licenses, and the curl
  license, may be borrowed from.
- A GPL-family source, for example tlsfuzzer, runs only as an external tool. Its
  code and its vectors are never copied into this repository.
- Any adaptation or verbatim copy is registered in this file in the same change
  that introduces it, and carries the upstream copyright and license text with
  it.
- A source is credited by name, upstream address, SPDX license, the version or
  commit checked and the level of borrowing, even when only its ideas were used.
- A level is recorded at the strongest level actually used. Unknown or unchecked
  facts are written as such and never assumed.

## Borrowing levels

- Idea or architecture: a design, seam or behavior was studied and informed an
  osistack decision. No upstream text, code or data entered this repository.
- Specification and vectors: test vectors or normative text taken from the
  source. Vectors are registered with their upstream location.
- Adaptation: code rewritten from the source's logic. Registered with the
  upstream copyright and license notice.
- Verbatim copy: upstream text or code copied unchanged. Registered with the
  upstream copyright and license notice.

## Registry fields

Each entry names the source project and upstream address, its SPDX license, the
version or commit checked and the date of the check, the borrowing level, the
osistack module it concerns, and the copyright and license notice that travels
with any copied material.

## Adopted sources

Checked against the upstream repositories on 2026-11-17. Every entry below is at
the idea or architecture level. No code, text or vector from any of them has
been copied or adapted into this repository.

| Source | Upstream | SPDX license | Checked | Level | osistack module | Copied notice |
|---|---|---|---|---|---|---|
| rustls | https://github.com/rustls/rustls | Apache-2.0 OR ISC OR MIT | release v/0.23.46 (rustls 0.23.46) | Idea or architecture | Contract for `crypto`, `tls` and the QUIC handshake seam; none yet | none |
| quinn-proto | https://github.com/quinn-rs/quinn | MIT OR Apache-2.0 | release quinn-proto-0.11.19 | Idea or architecture | Contract for sans-I/O `quic` and its simulation approach; none yet | none |
| h2 (hyperium) | https://github.com/hyperium/h2 | MIT | release v0.4.20 | Idea or architecture | Contract for `h2` flow control and HPACK; none yet | none |
| h3 (hyperium) | https://github.com/hyperium/h3 | MIT | tag h3-v0.0.8 (h3 0.0.8) | Idea or architecture | Contract for the `h3` transport seam; none yet | none |
| ureq | https://github.com/algesten/ureq | MIT OR Apache-2.0 | tag 3.5.2 (ureq 3.5.2) | Idea or architecture | Contract for the synchronous client shape and behavior baseline in `osistack`; none yet | none |
| curl | https://github.com/curl/curl | curl (SPDX `curl`, file COPYING) | tag curl-8_23_0 | Idea or architecture | Behavior baseline for the M5 command line; none yet | none |


## Runtime corpora

These files are read at test time from a path supplied through the environment.
Nothing from them is copied into this repository. The tests that use them are
ignored and do not gate default `cargo test` or Guard.

| Source | Upstream | SPDX license | Checked | Level | osistack module | Path |
|---|---|---|---|---|---|---|
| Wycheproof | https://github.com/google/wycheproof | Apache-2.0 | 2026-11-23, text vectors as shipped in the BoringSSL third_party snapshot checked on this machine | Specification and vectors, runtime only, not copied | Ignored osistack-crypto AEAD and X25519 tests | environment variable `OSISTACK_WYCHEPROOF` (a directory of the official `*_test.txt` files) |

## Planned, not yet adopted

These tools are intended for the verification ladder but nothing here uses them
yet, so they are not credits. Each is registered above when it is adopted, with
its license re-checked at that time. The license shown is the repository
license GitHub reported on 2026-11-17 and is informational only.

| Tool | Upstream | Reported license | Intended use |
|---|---|---|---|
| tlsfuzzer | https://github.com/tlsfuzzer/tlsfuzzer | GPL-2.0 | External tool only; no code or vectors copied |
| h2spec | https://github.com/summerwind/h2spec | MIT | External HTTP/2 conformance baseline |
| h3spec | https://github.com/kazu-yamamoto/h3spec | BSD-3-Clause | External HTTP/3 conformance baseline |
| QUIC Interop Runner | https://github.com/quic-interop/quic-interop-runner | not asserted by the repository | External QUIC interoperability baseline |
| BoGo | part of BoringSSL | not yet checked | External TLS conformance baseline |
| openssl, nghttpd | upstream projects | not yet checked | External differential peers |
