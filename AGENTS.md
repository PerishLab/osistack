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

Crate boundaries, protocol scope and platform contracts require explicit
modeling before their first implementation. Introduce production sources,
source scanning and release declarations with the capabilities they actually
implement. This baseline contains no network runtime or release.
