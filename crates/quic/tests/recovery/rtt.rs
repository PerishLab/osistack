use quic::{INITIAL, Rtt};

fn seeded() -> Rtt {
    let mut rtt = Rtt::new();
    rtt.update(1, 100_000, 0);
    rtt
}

#[test]
fn initial() {
    let rtt = Rtt::new();
    assert_eq!(rtt.smooth(), INITIAL);
    assert_eq!(rtt.smooth(), 333_000);
    assert_eq!(rtt.vary(), 166_500);
    assert_eq!(rtt.latest(), 0);
    assert_eq!(rtt.floor(), 0);
    assert_eq!(rtt.first(), None);
    assert_eq!(Rtt::default(), rtt);
}

#[test]
fn first() {
    let mut rtt = Rtt::new();
    rtt.update(7, 100_000, 40_000);
    assert_eq!(rtt.latest(), 100_000);
    assert_eq!(rtt.smooth(), 100_000);
    assert_eq!(rtt.vary(), 50_000);
    assert_eq!(rtt.floor(), 100_000);
    assert_eq!(rtt.first(), Some(7));
}

#[test]
fn second() {
    let mut rtt = seeded();
    rtt.update(9, 120_000, 10_000);
    assert_eq!(rtt.vary(), 40_000);
    assert_eq!(rtt.smooth(), 101_250);
    assert_eq!(rtt.latest(), 120_000);
    assert_eq!(rtt.floor(), 100_000);
    assert_eq!(rtt.first(), Some(1));
}

#[test]
fn implausible() {
    let mut rtt = seeded();
    rtt.update(9, 120_000, 10_000);
    rtt.update(11, 105_000, 20_000);
    assert_eq!(rtt.vary(), 30_937);
    assert_eq!(rtt.smooth(), 101_718);
}

#[test]
fn boundary() {
    let mut rtt = seeded();
    rtt.update(2, 120_000, 20_000);
    assert_eq!(rtt.smooth(), 100_000);
    let mut rtt = seeded();
    rtt.update(2, 119_999, 20_000);
    assert_eq!(rtt.smooth(), (700_000 + 119_999) / 8);
}

#[test]
fn floor() {
    let mut rtt = seeded();
    rtt.update(2, 80_000, 0);
    assert_eq!(rtt.floor(), 80_000);
    assert_eq!(rtt.vary(), 42_500);
    assert_eq!(rtt.smooth(), 97_500);
    rtt.update(3, 90_000, 5_000);
    assert_eq!(rtt.floor(), 80_000);
    assert_eq!(rtt.vary(), 35_000);
    assert_eq!(rtt.smooth(), 95_937);
}

#[test]
fn order() {
    let mut rtt = seeded();
    rtt.update(2, 200_000, 0);
    assert_eq!(rtt.vary(), 62_500);
    assert_eq!(rtt.smooth(), 112_500);
}

#[test]
fn huge() {
    let mut rtt = seeded();
    rtt.update(2, 1_000, u64::MAX);
    assert_eq!(rtt.latest(), 1_000);
    assert_eq!(rtt.floor(), 1_000);
    assert_eq!(rtt.smooth(), (700_000 + 1_000) / 8);
    rtt.update(3, u64::MAX, 0);
    assert!(rtt.smooth() > 0);
}
