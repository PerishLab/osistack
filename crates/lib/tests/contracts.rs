use osistack::{Area, Availability, Operation, Profile, Refusal, State, dispatch, help};

fn names(profile: &Profile, state: State) -> Vec<(Area, &'static str)> {
    profile
        .capabilities
        .iter()
        .filter(|c| c.state == state)
        .map(|c| (c.area, c.name))
        .collect()
}

#[test]
fn supported() {
    let profile = dispatch(Operation::Capabilities).unwrap();
    assert_eq!(
        names(&profile, State::Supported),
        vec![
            (Area::Wire, "byte-cursor"),
            (Area::Wire, "quic-varint"),
            (Area::Semantics, "method"),
            (Area::Semantics, "status"),
            (Area::Semantics, "field-name"),
            (Area::Semantics, "field-value"),
        ]
    );
}

#[test]
fn protocols() {
    let profile = Profile::current();
    for area in [
        Area::Http1,
        Area::Tls,
        Area::Http2,
        Area::Quic,
        Area::Http3,
        Area::Crypto,
        Area::Cli,
    ] {
        assert!(
            profile
                .capabilities
                .iter()
                .filter(|c| c.area == area)
                .all(|c| c.state != State::Supported),
            "{area:?}"
        );
    }
}

#[test]
fn exclusions() {
    let profile = Profile::current();
    let excluded = [
        (Area::Http1, "pipelining"),
        (Area::Http1, "upgrade"),
        (Area::Http1, "cookies"),
        (Area::Http1, "compression"),
        (Area::Tls, "tls12"),
        (Area::Tls, "resumption"),
        (Area::Tls, "zero-rtt"),
        (Area::Tls, "client-certificate"),
        (Area::Http2, "server-push"),
        (Area::Http2, "priority-tree"),
        (Area::Http2, "h2c-upgrade"),
        (Area::Quic, "cubic"),
        (Area::Quic, "bbr"),
        (Area::Quic, "connection-migration"),
        (Area::Quic, "zero-rtt"),
        (Area::Quic, "datagram"),
        (Area::Http3, "push"),
        (Area::Http3, "webtransport"),
        (Area::Scope, "userspace-tcpip"),
        (Area::Scope, "server-replacement"),
        (Area::Scope, "bootstrap-curl-replacement"),
        (Area::Scope, "full-curl-parity"),
    ];
    for (area, name) in excluded {
        assert_eq!(profile.state(area, name), Some(State::Excluded), "{name}");
    }
}

#[test]
fn pending() {
    let profile = Profile::current();
    let pending = [
        (Area::Http1, "proxy"),
        (Area::Http1, "chunked"),
        (Area::Tls, "x25519"),
        (Area::Tls, "explicit-pem-roots"),
        (Area::Http2, "hpack"),
        (Area::Quic, "ecn"),
        (Area::Quic, "gso"),
        (Area::Quic, "newreno"),
        (Area::Http3, "qpack"),
        (Area::Wire, "huffman"),
        (Area::Crypto, "primitives"),
        (Area::Cli, "curl-subset"),
    ];
    for (area, name) in pending {
        assert_eq!(profile.state(area, name), Some(State::Unverified), "{name}");
    }
    assert_eq!(profile.state(Area::Tls, "missing"), None);
}

#[test]
fn unique() {
    let profile = Profile::current();
    let mut seen = std::collections::HashSet::new();
    for c in &profile.capabilities {
        assert!(seen.insert((c.area as u8, c.name)), "{}", c.name);
    }
    assert_eq!(
        profile.count(State::Supported)
            + profile.count(State::Excluded)
            + profile.count(State::Unverified),
        profile.capabilities.len()
    );
}

#[test]
fn refused() {
    for operation in [Operation::Fetch, Operation::Serve] {
        assert_eq!(dispatch(operation), Err(Refusal::Unavailable(operation)));
    }
}

#[test]
fn guidance() {
    let entries = help();
    assert_eq!(entries.len(), 3);
    let available = entries
        .iter()
        .filter(|h| h.availability == Availability::Available)
        .map(|h| h.operation)
        .collect::<Vec<_>>();
    assert_eq!(available, vec![Operation::Capabilities]);
}

#[test]
fn facade() {
    assert_eq!(osistack::http::Status::new(200).unwrap().get(), 200);
    assert_eq!(osistack::wire::Varint::new(37).unwrap().get(), 37);
}
