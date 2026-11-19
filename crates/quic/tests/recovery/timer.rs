use crate::support::*;
use quic::{Fired, Recovery, Space};

#[test]
fn probe() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 1_000));
    assert_eq!(recovery.deadline(), Some(1_025_000));
    assert_eq!(recovery.expire(1_025_000), Fired::Probe(Space::Data));
    assert_eq!(recovery.pto(), 1);
    assert_eq!(recovery.deadline(), Some(2_049_000));
    assert_eq!(recovery.expire(2_049_000), Fired::Probe(Space::Data));
    assert_eq!(recovery.pto(), 2);
    assert_eq!(recovery.deadline(), Some(4_097_000));
}

#[test]
fn measured() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.acked(100_000, Space::Data, &ack(0, 0)).unwrap();
    assert_eq!(recovery.deadline(), None);
    recovery.sent(Space::Data, packet(1, 500_000));
    assert_eq!(recovery.deadline(), Some(825_000));
    recovery.sent(Space::Data, packet(2, 600_000));
    assert_eq!(recovery.deadline(), Some(925_000));
}

#[test]
fn flagged() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.sent(Space::Data, quiet(1, 10));
    recovery.sent(
        Space::Data,
        quic::Sent {
            eliciting: false,
            flight: true,
            ..packet(2, 20)
        },
    );
    assert_eq!(recovery.deadline(), Some(1_024_000));
}

#[test]
fn unconfirmed() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Data, packet(0, 0));
    assert_eq!(recovery.deadline(), None);
    recovery.confirm(500);
    assert_eq!(recovery.deadline(), Some(1_024_000));
}

#[test]
fn earliest() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 100));
    recovery.sent(Space::Handshake, packet(0, 50));
    recovery.sent(Space::Data, packet(0, 0));
    assert_eq!(recovery.deadline(), Some(999_050));
    assert_eq!(recovery.expire(999_050), Fired::Probe(Space::Handshake));
    let mut other = Recovery::new(false, 25_000, 3);
    other.sent(Space::Handshake, packet(0, 100));
    other.sent(Space::Initial, packet(0, 50));
    assert_eq!(other.expire(999_050), Fired::Probe(Space::Initial));
}

#[test]
fn server() {
    let mut recovery = Recovery::new(true, 25_000, 3);
    assert_eq!(recovery.deadline(), None);
    recovery.sent(Space::Initial, packet(0, 0));
    assert_eq!(recovery.deadline(), Some(999_000));
    recovery.expire(999_000);
    assert_eq!(recovery.pto(), 1);
    recovery
        .acked(1_000_000, Space::Initial, &ack(0, 0))
        .unwrap();
    assert_eq!(recovery.pto(), 0);
    assert_eq!(recovery.deadline(), None);
}

#[test]
fn blocked() {
    let mut recovery = Recovery::new(true, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.limit(10, true);
    assert_eq!(recovery.deadline(), None);
    recovery.limit(20, false);
    assert_eq!(recovery.deadline(), Some(999_000));
}

#[test]
fn pending() {
    let mut recovery = Recovery::new(true, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.sent(Space::Initial, packet(1, 0));
    recovery.acked(100_000, Space::Initial, &ack(1, 0)).unwrap();
    recovery.limit(100_001, true);
    assert_eq!(recovery.deadline(), Some(112_500));
}

#[test]
fn anti() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.acked(100_000, Space::Initial, &ack(0, 0)).unwrap();
    assert_eq!(recovery.deadline(), Some(400_000));
    assert_eq!(recovery.expire(400_000), Fired::Anti(Space::Initial));
    assert_eq!(recovery.pto(), 1);
    assert_eq!(recovery.deadline(), Some(1_000_000));
    recovery.confirm(1_000_001);
    assert_eq!(recovery.deadline(), None);
}

#[test]
fn keyed() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.keys();
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.acked(100_000, Space::Initial, &ack(0, 0)).unwrap();
    assert_eq!(recovery.expire(400_000), Fired::Anti(Space::Handshake));
}

#[test]
fn unvalidated() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.sent(Space::Initial, packet(1, 0));
    recovery.expire(999_000);
    recovery
        .acked(1_000_000, Space::Initial, &ack(0, 0))
        .unwrap();
    assert_eq!(recovery.pto(), 1);
}

#[test]
fn handshake() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Initial, packet(0, 0));
    recovery.sent(Space::Handshake, packet(0, 0));
    recovery.expire(999_000);
    recovery.expire(2_000_000);
    assert_eq!(recovery.pto(), 2);
    recovery
        .acked(2_100_000, Space::Handshake, &ack(0, 0))
        .unwrap();
    assert_eq!(recovery.pto(), 0);
}

#[test]
fn loss() {
    let mut recovery = client();
    burst(&mut recovery, Space::Data, 2, 0);
    recovery.acked(100_000, Space::Data, &ack(1, 0)).unwrap();
    assert_eq!(recovery.deadline(), Some(112_500));
    let fired = recovery.expire(112_500);
    assert_eq!(fired, Fired::Lost(Space::Data, vec![packet(0, 0)]));
    assert_eq!(recovery.pto(), 0);
    assert_eq!(recovery.deadline(), None);
}

#[test]
fn stray() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    let unflown = quic::Sent {
        flight: false,
        ..packet(1, 500)
    };
    recovery.sent(Space::Data, unflown);
    assert_eq!(recovery.deadline(), Some(1_024_000));
    recovery.limit(600, false);
    assert_eq!(recovery.deadline(), Some(1_024_000));
}

#[test]
fn nothing() {
    for (eliciting, flight) in [(false, true), (true, false), (false, false)] {
        let mut recovery = Recovery::new(true, 25_000, 3);
        let lone = quic::Sent {
            eliciting,
            flight,
            ..packet(0, 0)
        };
        recovery.sent(Space::Initial, lone);
        recovery.limit(10, false);
        assert_eq!(recovery.deadline(), None);
    }
}

#[test]
fn unarmed() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Initial, quiet(0, 100));
    assert_eq!(recovery.deadline(), None);
}

#[test]
fn granular() {
    let mut recovery = client();
    recovery.sent(Space::Data, packet(0, 0));
    recovery.acked(100, Space::Data, &ack(0, 0)).unwrap();
    recovery.sent(Space::Data, packet(1, 1_000));
    assert_eq!(recovery.deadline(), Some(27_100));
}

#[test]
fn simultaneous() {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.sent(Space::Handshake, packet(0, 0));
    recovery.sent(Space::Initial, packet(0, 0));
    assert_eq!(recovery.expire(999_000), Fired::Probe(Space::Initial));
}
