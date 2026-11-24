# osistack

A network stack built in the OSI-layer spirit, in the PerishLab domain.

Osistack aims to implement each layer itself so that it can be observed and
replaced on its own. Its first target is the widely used subset of HTTP/1.1,
HTTP/2 and HTTP/3, over a self-built TLS and a self-built QUIC, as a long-term
replacement for request libraries and curl in PerishLab.

- [Contract](https://github.com/PerishLab/osistack/issues/3), the decisions, scope and milestones.
- [AGENTS.md](AGENTS.md), the repository's working constraints.
- [CREDITS.md](CREDITS.md), the attribution registry and borrowing rules.
- [PerishLab delivery governance](https://github.com/PerishLab/.github/blob/main/GOVERNANCE.md),
  contribution and acceptance policy.

Licensed under the [MIT License](LICENSE).

## Usage

The curl-subset entry points are `osistack::command` and `osistack::applied`.
They take the same flag list a curl-style argv would, as `&[&str]`. This
repository does not ship an installed binary. The supported subset lives in
the [contract](https://github.com/PerishLab/osistack/issues/3).

```rust
use osistack::{applied, command};

// HTTP/1.1 over cleartext. Follow redirects and write the body to a file.
let response = command(&[
    "-L",
    "-o", "body.bin",
    "-H", "Accept: text/plain",
    "http://127.0.0.1:8080/path",
])?;

// HTTPS uses the system CA store by default. --cacert replaces it.
let outcome = applied(&[
    "--cacert", "ca.pem",
    "-I",
    "https://127.0.0.1:8443/",
])?;

// Prefer HTTP/3, falling back to TCP HTTPS if it fails.
let _ = command(&[
    "--http3",
    "--cacert", "ca.pem",
    "https://127.0.0.1:8443/",
])?;
```

An `https://` URL uses the system CA store by default. `--cacert FILE` or a
caller-set `Client.roots` replaces that store entirely. An empty root set, or a
host with no system store, returns an error that tells you to pass `--cacert
FILE`. `--http3` tries HTTP/3 and falls back to TCP HTTPS; `--http3-only` uses
HTTP/3 with no fallback. Both require `https://`. There is no `-k`.
