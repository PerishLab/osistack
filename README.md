# osistack

A network stack built in the OSI-layer spirit, in the PerishLab domain.

Osistack aims to implement each layer itself so that it can be observed and
replaced on its own. Its first target is the widely used subset of HTTP/1.1,
HTTP/2 and HTTP/3, over a self-built TLS and a self-built QUIC, as a long-term
replacement for request libraries and curl in PerishLab.

The workspace currently holds four crates and no client:

- `osistack`, the public entry, with a capability profile that separates what is
  supported, deliberately excluded and unverified. Operations that would touch a
  network are refused rather than faked.
- `http`, protocol-independent method, status, field name and field value types
  that validate and reject malformed input.
- `h1`, HTTP/1.1 response decoding over buffered bytes: status line, field
  section, body framing and the chunked coding, with ambiguous input refused.
- `wire`, a byte reader and writer and the QUIC variable-length integer of
  RFC 9000 section 16, the prefix integer of RFC 7541 section 5.1 and the
  Huffman code of RFC 7541 appendix B.

An HTTP/1.1 client, HTTP/2, HTTP/3, TLS, QUIC, cryptography and a command
line are not implemented, and nothing has been released, installed or
qualified on any platform. Designs and practices taken from other implementations will be
credited by name.

See [AGENTS.md](AGENTS.md) for the approved cold-start contract, the v0 subset
and the product's working constraints, [CREDITS.md](CREDITS.md) for the
attribution registry and borrowing rules, and the
[PerishLab delivery governance](https://github.com/PerishLab/.github/blob/main/GOVERNANCE.md)
for contribution and acceptance policy.

Licensed under the [MIT License](LICENSE).
