mod behaviour;
#[path = "../common/mod.rs"]
#[allow(dead_code)]
mod common;
mod flow;
mod http2;
mod http3;
mod quic;
mod reno;
mod rules;
mod seam;
mod tls;

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
            (Area::Wire, "prefix-integer"),
            (Area::Wire, "huffman"),
            (Area::Semantics, "method"),
            (Area::Semantics, "status"),
            (Area::Semantics, "field-name"),
            (Area::Semantics, "field-value"),
            (Area::Http1, "framing"),
            (Area::Http1, "content-length"),
            (Area::Http1, "chunked"),
            (Area::Http1, "connection-close"),
            (Area::Http1, "http10-response"),
            (Area::Http1, "smuggling-defense"),
            (Area::Http1, "status-not-error"),
            (Area::Tls, "hostname-validation"),
            (Area::Tls, "explicit-pem-roots"),
            (Area::Http2, "hpack"),
            (Area::Quic, "version-negotiation"),
            (Area::Quic, "stream-flow-control"),
            (Area::Quic, "connection-flow-control"),
            (Area::Quic, "connection-id"),
            (Area::Quic, "path-validation"),
            (Area::Quic, "newreno"),
            (Area::Http3, "control-stream"),
            (Area::Http3, "settings"),
            (Area::Http3, "headers"),
            (Area::Http3, "data"),
            (Area::Http3, "qpack"),
            (Area::Http3, "blocked-streams"),
            (Area::Http3, "goaway"),
            (Area::Http3, "alt-svc-discovery"),
            (Area::Crypto, "seam"),
        ]
    );
}

#[test]
fn protocols() {
    let profile = Profile::current();
    assert!(
        profile
            .capabilities
            .iter()
            .filter(|c| c.area == Area::Cli)
            .all(|c| c.state != State::Supported)
    );
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
        (Area::Http1, "keep-alive-pool"),
        (Area::Http1, "redirect-policy"),
        (Area::Http1, "total-timeout"),
        (Area::Http1, "phase-timeout"),
        (Area::Http1, "loopback-test-server"),
        (Area::Tls, "x25519"),
        (Area::Tls, "sni"),
        (Area::Tls, "alpn"),
        (Area::Tls, "chain-validation"),
        (Area::Http2, "settings"),
        (Area::Http2, "headers"),
        (Area::Http2, "data"),
        (Area::Http2, "flow-control"),
        (Area::Quic, "v1"),
        (Area::Quic, "retry-handshake"),
        (Area::Quic, "key-update"),
        (Area::Quic, "ecn"),
        (Area::Quic, "gso"),
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
    assert_eq!(profile.count(State::Supported), 33);
    assert_eq!(profile.count(State::Excluded), 32);
    assert_eq!(profile.count(State::Unverified), 34);
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

#[test]
fn behaved() {
    let profile = Profile::current();
    let tables = [
        (Area::Http1, behaviour::table()),
        (Area::Http2, http2::table()),
        (Area::Http3, http3::table()),
        (Area::Quic, quic::table()),
        (Area::Tls, tls::table()),
        (Area::Crypto, seam::table()),
    ];
    for (area, rows) in tables {
        let mut declared: Vec<&str> = profile
            .capabilities
            .iter()
            .filter(|c| c.area == area && c.state == State::Supported)
            .map(|c| c.name)
            .collect();
        let mut named: Vec<&str> = rows.iter().map(|row| row.0).collect();
        declared.sort_unstable();
        named.sort_unstable();
        assert_eq!(named, declared, "{area:?}");
        let mut failed = Vec::new();
        for (name, check) in rows {
            if std::thread::spawn(check).join().is_err() {
                failed.push(format!("{area:?} {name}"));
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }
}
