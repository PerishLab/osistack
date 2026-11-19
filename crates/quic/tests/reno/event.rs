use crate::support::*;
use quic::Reno;

#[test]
fn halve() {
    let mut reno = Reno::new(1200, 25_000);
    reno.sent(&packet(0, 100));
    reno.lost(500, &[packet(0, 100)], &measured());
    assert_eq!(reno.window(), 6_000);
    assert_eq!(reno.threshold(), Some(6_000));
    assert_eq!(reno.start(), Some(500));
    assert_eq!(reno.flight(), 0);
}

#[test]
fn floor() {
    let mut reno = Reno::new(1200, 25_000);
    let rtt = measured();
    reno.lost(500, &[packet(0, 100)], &rtt);
    assert_eq!(reno.window(), 6_000);
    reno.lost(900, &[packet(1, 600)], &rtt);
    assert_eq!(reno.window(), 3_000);
    assert_eq!(reno.threshold(), Some(3_000));
    reno.lost(1_300, &[packet(2, 1_000)], &rtt);
    assert_eq!(reno.window(), 2_400);
    assert_eq!(reno.threshold(), Some(1_500));
    let mut large = Reno::new(9_000, 25_000);
    large.lost(500, &[packet(0, 100)], &rtt);
    assert_eq!(large.window(), 18_000);
    assert_eq!(large.threshold(), Some(9_000));
}

#[test]
fn repeat() {
    let mut reno = Reno::new(1200, 25_000);
    let rtt = measured();
    reno.lost(500, &[packet(0, 100)], &rtt);
    reno.lost(600, &[packet(1, 300)], &rtt);
    assert_eq!(reno.window(), 6_000);
    assert_eq!(reno.start(), Some(500));
    reno.lost(600, &[packet(2, 500)], &rtt);
    assert_eq!(reno.window(), 6_000);
    assert_eq!(reno.start(), Some(500));
    reno.lost(700, &[packet(3, 501)], &rtt);
    assert_eq!(reno.window(), 3_000);
    assert_eq!(reno.start(), Some(700));
}

#[test]
fn latest() {
    let mut reno = Reno::new(1200, 25_000);
    let rtt = measured();
    reno.lost(500, &[packet(0, 100)], &rtt);
    reno.lost(600, &[packet(1, 300), packet(2, 550)], &rtt);
    assert_eq!(reno.window(), 3_000);
    assert_eq!(reno.start(), Some(600));
}

#[test]
fn frozen() {
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(500, &[packet(0, 100)], &measured());
    let batch = [
        packet(1, 500),
        packet(2, 501),
        packet(3, 501),
        packet(4, 501),
        packet(5, 501),
    ];
    for each in &batch {
        reno.sent(each);
    }
    reno.acked(&batch);
    assert_eq!(reno.window(), 6_000);
    assert_eq!(reno.flight(), 0);
}

#[test]
fn regrow() {
    let mut reno = Reno::new(1200, 25_000);
    let rtt = measured();
    reno.lost(2_000_000, &[packet(0, 150_000)], &rtt);
    assert_eq!(reno.window(), 6_000);
    reno.lost(2_100_000, &strip(10, 8, 200_000, 1_175_001), &rtt);
    assert_eq!(reno.window(), 2_400);
    assert_eq!(reno.start(), None);
    assert_eq!(reno.threshold(), Some(6_000));
    let mut seen = Vec::new();
    for number in 0..5 {
        reno.acked(&[packet(number, 3_000_000)]);
        seen.push(reno.window());
    }
    assert_eq!(seen, [3_600, 4_800, 6_000, 6_000, 6_000]);
}

#[test]
fn newest() {
    let mut reno = Reno::new(1200, 25_000);
    let rtt = measured();
    reno.lost(500, &[packet(0, 100)], &rtt);
    reno.lost(600, &[packet(2, 550), packet(1, 300)], &rtt);
    assert_eq!(reno.window(), 3_000);
    assert_eq!(reno.start(), Some(600));
}
