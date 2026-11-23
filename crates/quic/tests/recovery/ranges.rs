use crate::support::*;
use quic::{Ack, Error, Fired, Space};

#[test]
fn spans() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 10, 0);
    let frame = Ack {
        largest: 9,
        delay: 0,
        first: 1,
        ranges: vec![(2, 1)],
        ecn: None,
    };
    let out = recovery.acked(100, Space::Data, &frame).unwrap();
    assert_eq!(numbers(&out.acked), [3, 4, 8, 9]);
    assert_eq!(numbers(&out.lost), [0, 1, 2, 5, 6]);
    assert_eq!(recovery.loss(Space::Data), Some(1_000));
}

#[test]
fn multiple() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 12, 0);
    let frame = Ack {
        largest: 11,
        delay: 0,
        first: 0,
        ranges: vec![(0, 0), (1, 1)],
        ecn: None,
    };
    let out = recovery.acked(100, Space::Data, &frame).unwrap();
    assert_eq!(numbers(&out.acked), [5, 6, 9, 11]);
}

#[test]
fn duplicate() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.sent(Space::Data, packet(1, 0));
    let first = recovery.deadline().unwrap();
    assert_eq!(recovery.expire(first), Fired::Probe(Space::Data));
    recovery.acked(200_000, Space::Data, &ack(1, 1)).unwrap();
    assert_eq!(recovery.pto(), 0);
    recovery.sent(Space::Data, packet(2, 210_000));
    let next = recovery.deadline().unwrap();
    recovery.expire(next);
    assert_eq!(recovery.pto(), 1);
    let before = recovery.rtt().clone();
    let stamp = recovery.deadline();
    let out = recovery.acked(300_000, Space::Data, &ack(1, 1)).unwrap();
    assert!(out.acked.is_empty() && out.lost.is_empty());
    assert_eq!(recovery.pto(), 1);
    assert_eq!(recovery.rtt(), &before);
    assert_eq!(recovery.deadline(), stamp);
}

#[test]
fn stale() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(4, 0));
    let out = recovery.acked(100_000, Space::Data, &ack(5, 1)).unwrap();
    assert_eq!(numbers(&out.acked), [4]);
    assert_eq!(recovery.rtt().first(), None);
}

#[test]
fn silent() {
    let mut recovery = client();
    recovery.sent(Space::Data, quiet(0, 0));
    let out = recovery.acked(100_000, Space::Data, &ack(0, 0)).unwrap();
    assert_eq!(numbers(&out.acked), [0]);
    assert_eq!(recovery.rtt().first(), None);
}

#[test]
fn mixed() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.sent(Space::Data, quiet(1, 20_000));
    recovery.acked(100_000, Space::Data, &ack(1, 1)).unwrap();
    assert_eq!(recovery.rtt().latest(), 80_000);
    assert_eq!(recovery.rtt().first(), Some(100_000));
}

fn second(recovery: &mut quic::Recovery, space: Space, delay: u64) {
    recovery.sent(space, packet(0, 0));
    recovery.acked(100_000, space, &ack(0, 0)).unwrap();
    recovery.sent(space, packet(1, 200_000));
    let frame = Ack { delay, ..ack(1, 0) };
    recovery.acked(420_000, space, &frame).unwrap();
}

#[test]
fn scaled() {
    let mut recovery = quic::Recovery::new(false, 25_000, 3);
    second(&mut recovery, Space::Data, 100);
    assert_eq!(recovery.rtt().latest(), 220_000);
    assert_eq!(recovery.rtt().vary(), (150_000 + 120_000 - 800) / 4);
    assert_eq!(recovery.rtt().smooth(), (700_000 + 220_000 - 800) / 8);
}

#[test]
fn unclamped() {
    let mut recovery = quic::Recovery::new(false, 25_000, 3);
    second(&mut recovery, Space::Data, 10_000);
    assert_eq!(recovery.rtt().vary(), 47_500);
    assert_eq!(recovery.rtt().smooth(), 105_000);
}

#[test]
fn clamped() {
    let mut recovery = quic::Recovery::new(false, 25_000, 3);
    recovery.confirm(0);
    second(&mut recovery, Space::Data, 10_000);
    assert_eq!(recovery.rtt().vary(), 61_250);
    assert_eq!(recovery.rtt().smooth(), 111_875);
}

#[test]
fn capped() {
    let mut recovery = quic::Recovery::new(false, 25_000, 30);
    recovery.sent(Space::Data, packet(0, 0));
    recovery.acked(100_000, Space::Data, &ack(0, 0)).unwrap();
    recovery.sent(Space::Data, packet(1, 200_000));
    let frame = Ack {
        delay: 1,
        ..ack(1, 0)
    };
    recovery.acked(4_200_000, Space::Data, &frame).unwrap();
    assert_eq!(recovery.rtt().vary(), 750_356);
    assert_eq!(recovery.rtt().smooth(), 456_428);
}

#[test]
fn initial() {
    let mut recovery = quic::Recovery::new(false, 25_000, 3);
    second(&mut recovery, Space::Initial, 1_000);
    assert_eq!(recovery.rtt().vary(), 67_500);
    assert_eq!(recovery.rtt().smooth(), 115_000);
}

#[test]
fn invalid() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 4, 0);
    let bad = ack(3, 5);
    assert_eq!(recovery.acked(500, Space::Data, &bad), Err(Error::Value));
    assert_eq!(recovery.rtt().first(), None);
    let out = recovery.acked(500, Space::Data, &ack(3, 0)).unwrap();
    assert_eq!(numbers(&out.acked), [3]);
}

#[test]
fn monotonic() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 7, 0);
    recovery.acked(100, Space::Data, &ack(6, 0)).unwrap();
    assert_eq!(recovery.loss(Space::Data), Some(1_000));
    recovery.acked(200, Space::Data, &ack(4, 0)).unwrap();
    assert_eq!(recovery.loss(Space::Data), Some(1_000));
}

#[test]
fn rewind() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 6, 1_000);
    let out = recovery.acked(100, Space::Data, &ack(5, 5)).unwrap();
    assert_eq!(numbers(&out.acked), [0, 1, 2, 3, 4, 5]);
    let later = recovery.acked(50, Space::Data, &ack(5, 5)).unwrap();
    assert!(later.acked.is_empty());
}

#[test]
fn refused() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 4, 0);
    let mut bad = ack(3, 0);
    bad.first = 4;
    assert_eq!(recovery.acked(500, Space::Data, &bad), Err(Error::Value));
    bad = ack(3, 0);
    bad.ranges.push((8, 0));
    assert_eq!(recovery.acked(500, Space::Data, &bad), Err(Error::Value));
}
