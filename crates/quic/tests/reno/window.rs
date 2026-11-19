use crate::support::*;
use quic::{Reno, Rtt};

#[test]
fn initial() {
    let table = [
        (1200, 12_000),
        (1500, 14_720),
        (1000, 10_000),
        (9000, 18_000),
        (1471, 14_710),
        (1472, 14_720),
        (1473, 14_720),
        (7400, 14_800),
    ];
    for (datagram, window) in table {
        let reno = Reno::new(datagram, 25_000);
        assert_eq!(reno.window(), window);
        assert_eq!(reno.room(), window);
        assert_eq!(reno.flight(), 0);
        assert_eq!(reno.threshold(), None);
        assert_eq!(reno.start(), None);
    }
}

#[test]
fn counted() {
    let mut reno = Reno::new(1200, 25_000);
    reno.sent(&packet(0, 0));
    reno.sent(&packet(1, 0));
    reno.sent(&quiet(2, 0));
    assert_eq!(reno.flight(), 2_400);
    assert_eq!(reno.room(), 9_600);
}

#[test]
fn probes() {
    let mut reno = Reno::new(1200, 25_000);
    for number in 0..11 {
        reno.sent(&packet(number, 0));
    }
    assert_eq!(reno.flight(), 13_200);
    assert_eq!(reno.room(), 0);
}

#[test]
fn slow() {
    let mut reno = Reno::new(1200, 25_000);
    let batch = [packet(0, 0), packet(1, 0), packet(2, 0)];
    for each in &batch {
        reno.sent(each);
    }
    reno.acked(&batch);
    assert_eq!(reno.window(), 15_600);
    assert_eq!(reno.flight(), 0);
    assert_eq!(reno.threshold(), None);
}

#[test]
fn plain() {
    let mut reno = Reno::new(1200, 25_000);
    reno.sent(&packet(0, 0));
    reno.acked(&[quiet(1, 0)]);
    assert_eq!(reno.flight(), 1_200);
    assert_eq!(reno.window(), 12_000);
    reno.lost(500, &[quiet(2, 0)], &measured());
    assert_eq!(reno.window(), 12_000);
    assert_eq!(reno.flight(), 1_200);
    assert_eq!(reno.start(), None);
}

#[test]
fn paused() {
    let mut reno = Reno::new(1200, 25_000);
    reno.limited(true);
    let batch = [packet(0, 0), packet(1, 0)];
    for each in &batch {
        reno.sent(each);
    }
    reno.acked(&batch);
    assert_eq!(reno.flight(), 0);
    assert_eq!(reno.window(), 12_000);
    reno.limited(false);
    reno.sent(&packet(2, 0));
    reno.acked(&[packet(2, 0)]);
    assert_eq!(reno.window(), 13_200);
}

#[test]
fn drain() {
    let mut reno = Reno::new(1200, 25_000);
    reno.sent(&packet(0, 0));
    reno.discard(&[quiet(1, 0)]);
    assert_eq!(reno.flight(), 1_200);
    reno.discard(&[packet(0, 0), packet(1, 0), packet(2, 0)]);
    assert_eq!(reno.flight(), 0);
    reno.acked(&[packet(3, 0)]);
    assert_eq!(reno.flight(), 0);
}

#[test]
fn tiny() {
    let mut reno = Reno::new(0, 0);
    assert_eq!(reno.window(), 10);
    reno.lost(10, &[packet(0, 0)], &Rtt::new());
    assert_eq!(reno.window(), 5);
    assert_eq!(reno.threshold(), Some(5));
    reno.acked(&[packet(1, 20)]);
    assert_eq!(reno.window(), 245);
}

#[test]
fn sized() {
    let mut reno = Reno::new(1200, 25_000);
    let small = quic::Sent {
        size: 700,
        ..packet(0, 0)
    };
    let large = quic::Sent {
        size: 3_000,
        ..packet(1, 0)
    };
    reno.acked(&[small]);
    assert_eq!(reno.window(), 12_700);
    reno.acked(&[large]);
    assert_eq!(reno.window(), 15_700);
}
