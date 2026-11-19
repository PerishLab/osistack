use crate::support::*;
use quic::{Fired, Recovery, Space};

fn scene(first: Space, second: Space) -> Recovery {
    let mut recovery = client();
    recovery.sent(first, packet(0, 0));
    recovery.sent(first, packet(1, 0));
    recovery.acked(100_000, first, &ack(1, 0)).unwrap();
    recovery.sent(second, packet(0, 50_000));
    recovery.sent(second, packet(1, 50_000));
    recovery.acked(150_000, second, &ack(1, 0)).unwrap();
    recovery
}

#[test]
fn lowest() {
    for (first, second) in [(Space::Initial, Space::Data), (Space::Data, Space::Initial)] {
        let mut recovery = scene(first, second);
        assert_eq!(recovery.loss(first), Some(112_500));
        assert_eq!(recovery.loss(second), Some(162_500));
        assert_eq!(recovery.deadline(), Some(112_500));
        let fired = recovery.expire(112_500);
        assert_eq!(fired, Fired::Lost(first, vec![packet(0, 0)]));
        assert_eq!(recovery.deadline(), Some(162_500));
    }
}

#[test]
fn tied() {
    let mut recovery = client();
    for space in [Space::Data, Space::Handshake, Space::Initial] {
        recovery.sent(space, packet(0, 0));
        recovery.sent(space, packet(1, 0));
        recovery.acked(100_000, space, &ack(1, 0)).unwrap();
    }
    assert_eq!(recovery.deadline(), Some(112_500));
    let fired = recovery.expire(112_500);
    assert_eq!(fired, Fired::Lost(Space::Initial, vec![packet(0, 0)]));
    let fired = recovery.expire(112_500);
    assert_eq!(fired, Fired::Lost(Space::Handshake, vec![packet(0, 0)]));
}

#[test]
fn discard() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.sent(Space::Initial, quiet(1, 0));
    recovery.sent(Space::Handshake, packet(0, 100));
    assert_eq!(recovery.deadline(), Some(999_000));
    assert_eq!(recovery.expire(999_000), Fired::Probe(Space::Initial));
    assert_eq!(recovery.pto(), 1);
    let gone = recovery.discard(1_000_000, Space::Initial);
    assert_eq!(gone, vec![packet(0, 0)]);
    assert_eq!(recovery.pto(), 0);
    assert_eq!(recovery.deadline(), Some(999_100));
    let again = recovery
        .acked(1_000_001, Space::Initial, &ack(1, 1))
        .unwrap();
    assert!(again.acked.is_empty());
}

#[test]
fn forget() {
    let mut recovery = client();
    burst(&mut recovery, Space::Initial, 2, 0);
    recovery.acked(100_000, Space::Initial, &ack(1, 0)).unwrap();
    assert_eq!(recovery.loss(Space::Initial), Some(112_500));
    let gone = recovery.discard(100_001, Space::Initial);
    assert_eq!(gone, vec![packet(0, 0)]);
    assert_eq!(recovery.loss(Space::Initial), None);
    assert_eq!(recovery.deadline(), None);
}

#[test]
fn separate() {
    let mut recovery = client();
    burst(&mut recovery, Space::Initial, 2, 0);
    burst(&mut recovery, Space::Data, 2, 0);
    let out = recovery.acked(100, Space::Initial, &ack(1, 1)).unwrap();
    assert_eq!(numbers(&out.acked), [0, 1]);
    let out = recovery.acked(100, Space::Data, &ack(1, 0)).unwrap();
    assert_eq!(numbers(&out.acked), [1]);
    assert_eq!(recovery.loss(Space::Initial), None);
    assert_eq!(recovery.loss(Space::Data), Some(1_000));
}
