use crate::support::*;
use quic::{Fired, Space};

fn pair(time: u64) -> quic::Recovery {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, time));
    recovery.sent(Space::Data, packet(1, time));
    recovery
}

#[test]
fn threshold() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 4, 0);
    let out = recovery.acked(500, Space::Data, &ack(3, 0)).unwrap();
    assert_eq!(numbers(&out.acked), [3]);
    assert_eq!(numbers(&out.lost), [0]);
    assert_eq!(recovery.loss(Space::Data), Some(1_000));
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 3, 0);
    let out = recovery.acked(500, Space::Data, &ack(2, 0)).unwrap();
    assert_eq!(numbers(&out.acked), [2]);
    assert!(out.lost.is_empty());
}

#[test]
fn window() {
    let mut recovery = pair(0);
    let out = recovery.acked(100_000, Space::Data, &ack(1, 0)).unwrap();
    assert!(out.lost.is_empty());
    assert_eq!(recovery.loss(Space::Data), Some(112_500));
    assert_eq!(recovery.deadline(), Some(112_500));
    let fired = recovery.expire(112_500);
    assert_eq!(fired, Fired::Lost(Space::Data, vec![packet(0, 0)]));
    let mut early = pair(0);
    early.acked(100_000, Space::Data, &ack(1, 0)).unwrap();
    assert_eq!(early.expire(112_499), Fired::Lost(Space::Data, Vec::new()));
    assert_eq!(early.loss(Space::Data), Some(112_500));
}

#[test]
fn inline() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.sent(Space::Data, packet(1, 12_500));
    let out = recovery.acked(112_500, Space::Data, &ack(1, 0)).unwrap();
    assert_eq!(numbers(&out.lost), [0]);
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.sent(Space::Data, packet(1, 12_499));
    let out = recovery.acked(112_499, Space::Data, &ack(1, 0)).unwrap();
    assert!(out.lost.is_empty());
    assert_eq!(recovery.loss(Space::Data), Some(112_500));
}

#[test]
fn floor() {
    let mut recovery = pair(0);
    recovery.acked(100, Space::Data, &ack(1, 0)).unwrap();
    assert_eq!(recovery.loss(Space::Data), Some(1_000));
}

#[test]
fn larger() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.acked(100_000, Space::Data, &ack(0, 0)).unwrap();
    recovery.sent(Space::Data, packet(1, 200_000));
    recovery.sent(Space::Data, packet(2, 200_000));
    recovery.acked(400_000, Space::Data, &ack(2, 0)).unwrap();
    assert_eq!(recovery.rtt().latest(), 200_000);
    assert_eq!(recovery.rtt().smooth(), 112_500);
    assert_eq!(recovery.loss(Space::Data), Some(425_000));
}

#[test]
fn smaller() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.acked(100_000, Space::Data, &ack(0, 0)).unwrap();
    recovery.sent(Space::Data, packet(1, 200_000));
    recovery.sent(Space::Data, packet(2, 200_000));
    recovery.acked(250_000, Space::Data, &ack(2, 0)).unwrap();
    assert_eq!(recovery.rtt().smooth(), 93_750);
    assert_eq!(recovery.loss(Space::Data), Some(305_468));
}

#[test]
fn sparse() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(1, 0));
    recovery.sent(Space::Data, packet(5, 0));
    let out = recovery.acked(100, Space::Data, &ack(5, 0)).unwrap();
    assert_eq!(numbers(&out.lost), [1]);
    assert_eq!(numbers(&out.acked), [5]);
}

#[test]
fn removed() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 4, 0);
    recovery.acked(500, Space::Data, &ack(3, 0)).unwrap();
    let again = recovery.acked(600, Space::Data, &ack(3, 3)).unwrap();
    assert_eq!(numbers(&again.acked), [1, 2]);
    assert!(again.lost.is_empty());
}

#[test]
fn soonest() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.sent(Space::Data, packet(1, 5_000));
    recovery.sent(Space::Data, packet(2, 5_000));
    let out = recovery.acked(105_000, Space::Data, &ack(2, 0)).unwrap();
    assert!(out.lost.is_empty());
    assert_eq!(recovery.loss(Space::Data), Some(112_500));
}
