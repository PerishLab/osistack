use crate::data::*;
use crate::support::*;

#[test]
fn client() {
    let wire = hex(CLIENT);
    assert_eq!(wire.len(), 201);
    let (record, offer) = offer(&wire);
    assert_eq!(record.version, 0x0301);
    assert_eq!(record.fragment.len(), 196);
    assert_eq!(record.fragment[4..].len(), 192);
    let random = "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7";
    assert_eq!(offer.random.to_vec(), hex(random));
    assert!(offer.session.is_empty());
    assert_eq!(offer.suites, vec![0x1301, 0x1303, 0x1302]);
    let expected = vec![0x00, 0xff01, 0x0a, 0x23, 0x33, 0x2b, 0x0d, 0x2d, 0x1c];
    assert_eq!(kinds(&offer.extensions), expected);
    assert_eq!(offer.extensions[0].data, hex("0009 00 0006 736572766572"));
}

#[test]
fn server() {
    let wire = hex(SERVER);
    assert_eq!(wire.len(), 95);
    let (record, reply) = reply(&wire);
    assert_eq!(record.version, 0x0303);
    assert_eq!(record.fragment.len(), 90);
    assert_eq!(reply.suite, 0x1301);
    assert!(reply.session.is_empty());
    assert_eq!(kinds(&reply.extensions), vec![0x33, 0x2b]);
    assert_eq!(reply.extensions[1].data, hex("0304"));
    assert!(!reply.retry());
}

#[test]
fn early() {
    let wire = hex(EARLY);
    assert_eq!(wire.len(), 517);
    let (record, offer) = offer(&wire);
    assert_eq!(record.version, 0x0301);
    let found = kinds(&offer.extensions);
    assert!(found.contains(&0x2a));
    assert_eq!(found.last(), Some(&0x29));
}

#[test]
fn retry() {
    let (first, one) = offer(&hex(FIRST));
    assert_eq!(first.version, 0x0301);
    assert!(!one.extensions.is_empty());
    let wire = hex(RETRY);
    assert_eq!(wire.len(), 181);
    let (_, reply) = reply(&wire);
    assert!(reply.retry());
    assert_eq!(reply.suite, 0x1301);
    assert!(kinds(&reply.extensions).contains(&0x2b));
    let (second, two) = offer(&hex(SECOND));
    assert_eq!(second.version, 0x0303);
    assert_eq!(second.fragment.len(), 512);
    assert_eq!(hex(SECOND).len(), 517);
    assert_eq!(two.random, one.random);
    assert_ne!(kinds(&two.extensions), kinds(&one.extensions));
}

#[test]
fn last() {
    let wire = hex(FINAL);
    assert_eq!(wire.len(), 128);
    let (_, reply) = reply(&wire);
    assert!(!reply.retry());
    assert_eq!(kinds(&reply.extensions), vec![0x33, 0x2b]);
}
