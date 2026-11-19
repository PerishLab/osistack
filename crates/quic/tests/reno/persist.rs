use crate::support::*;
use quic::{Reno, Rtt};

fn period(delay: u64, width: u64) -> Reno {
    let mut reno = Reno::new(1200, delay);
    let rtt = measured();
    reno.lost(5_000_000, &strip(2, 7, 200_000, 200_000 + width), &rtt);
    reno
}

fn crushed(reno: &Reno) -> bool {
    reno.window() == 2_400 && reno.start().is_none()
}

#[test]
fn exact() {
    let reno = period(25_000, 975_000);
    assert_eq!(reno.window(), 6_000);
    assert_eq!(reno.start(), Some(5_000_000));
    let reno = period(25_000, 975_001);
    assert!(crushed(&reno));
    assert_eq!(reno.threshold(), Some(6_000));
}

#[test]
fn padded() {
    assert!(!crushed(&period(0, 900_000)));
    assert!(crushed(&period(0, 900_001)));
    assert!(!crushed(&period(25_000, 900_001)));
}

#[test]
fn unmeasured() {
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(5_000_000, &strip(2, 7, 200_000, 9_000_000), &Rtt::new());
    assert_eq!(reno.window(), 6_000);
}

#[test]
fn early() {
    let mut reno = Reno::new(1200, 25_000);
    let list = [packet(2, 100_000), packet(3, 200_000), packet(4, 1_175_000)];
    reno.lost(5_000_000, &list, &measured());
    assert_eq!(reno.window(), 6_000);
    let mut reno = Reno::new(1200, 25_000);
    let list = [packet(2, 100_001), packet(3, 200_000), packet(4, 1_075_002)];
    reno.lost(5_000_000, &list, &measured());
    assert!(crushed(&reno));
}

#[test]
fn ends() {
    let mut reno = Reno::new(1200, 25_000);
    let list = [packet(2, 200_000), quiet(3, 2_000_000)];
    reno.lost(5_000_000, &list, &measured());
    assert_eq!(reno.window(), 6_000);
    let mut reno = Reno::new(1200, 25_000);
    let list = [packet(2, 200_000), quiet(3, 300_000), packet(4, 1_200_000)];
    reno.lost(5_000_000, &list, &measured());
    assert!(crushed(&reno));
    let mut reno = Reno::new(1200, 25_000);
    let list = [packet(2, 200_000), packet(3, 300_000), quiet(4, 3_000_000)];
    reno.lost(5_000_000, &list, &measured());
    assert_eq!(reno.window(), 6_000);
}

#[test]
fn gap() {
    let mut reno = Reno::new(1200, 25_000);
    let list = [
        packet(2, 200_000),
        packet(3, 300_000),
        packet(5, 1_100_000),
        packet(6, 1_200_000),
    ];
    reno.lost(5_000_000, &list, &measured());
    assert_eq!(reno.window(), 6_000);
    let mut whole = Reno::new(1200, 25_000);
    let list = [
        packet(2, 200_000),
        packet(3, 300_000),
        packet(4, 400_000),
        packet(5, 1_100_000),
        packet(6, 1_200_000),
    ];
    whole.lost(5_000_000, &list, &measured());
    assert!(crushed(&whole));
}

#[test]
fn shuffled() {
    let mut reno = Reno::new(1200, 25_000);
    let mut list = strip(2, 7, 200_000, 1_175_001);
    list.reverse();
    reno.lost(5_000_000, &list, &measured());
    assert!(crushed(&reno));
}

#[test]
fn granular() {
    let mut rtt = Rtt::new();
    rtt.update(100, 100, 0);
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(5_000_000, &strip(2, 7, 200, 200 + 78_000), &rtt);
    assert_eq!(reno.window(), 6_000);
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(5_000_000, &strip(2, 7, 200, 200 + 78_301), &rtt);
    assert!(crushed(&reno));
}

#[test]
fn wide() {
    let mut rtt = Rtt::new();
    rtt.update(100_000, 100_000, 0);
    rtt.update(100_001, 100_000, 0);
    let mut reno = Reno::new(1200, 0);
    reno.lost(5_000_000, &strip(2, 7, 200_000, 200_000 + 750_000), &rtt);
    assert_eq!(reno.window(), 6_000);
    let mut reno = Reno::new(1200, 0);
    reno.lost(5_000_000, &strip(2, 7, 200_000, 200_000 + 750_001), &rtt);
    assert!(crushed(&reno));
}

#[test]
fn reset() {
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(5_000_000, &strip(2, 7, 200_000, 1_175_001), &measured());
    assert!(crushed(&reno));
    reno.acked(&[packet(20, 6_000_000)]);
    assert_eq!(reno.window(), 3_600);
}

#[test]
fn empty() {
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(5_000_000, &[], &measured());
    assert_eq!(reno.window(), 12_000);
    assert_eq!(reno.start(), None);
}

#[test]
fn stale() {
    let mut reno = Reno::new(1200, 25_000);
    let rtt = measured();
    reno.lost(2_000_000, &[packet(0, 150_000)], &rtt);
    for number in 1..5 {
        reno.acked(&[packet(number, 2_000_001)]);
    }
    assert_eq!(reno.window(), 6_000);
    reno.lost(2_100_000, &strip(10, 8, 200_000, 1_175_001), &rtt);
    assert!(crushed(&reno));
    let mut seen = Vec::new();
    for number in 20..24 {
        reno.acked(&[packet(number, 3_000_000)]);
        seen.push(reno.window());
    }
    assert_eq!(seen, [3_600, 4_800, 6_000, 6_000]);
}
