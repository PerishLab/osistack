# osistack

A network stack built in the OSI-layer spirit, in the PerishLab domain.

Osistack aims to implement each layer itself so that it can be observed and
replaced on its own. Its first target is the widely used subset of HTTP/1.1,
HTTP/2 and HTTP/3, over a self-built TLS and a self-built QUIC, as a long-term
replacement for request libraries and curl in PerishLab.

The repository currently contains its governance baseline. Protocol behavior,
crate boundaries, supported platforms and distribution are not yet implemented.
Designs and practices taken from other implementations will be credited by name.

See [AGENTS.md](AGENTS.md) for the product's working constraints and the
[PerishLab delivery governance](https://github.com/PerishLab/.github/blob/main/GOVERNANCE.md)
for contribution and acceptance policy.

Licensed under the [MIT License](LICENSE).
