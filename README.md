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
