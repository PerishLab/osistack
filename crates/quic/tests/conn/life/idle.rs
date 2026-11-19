use quic::Idle;

#[test]
fn none() {
    let idle = Idle::new(0, 0, 0);
    assert_eq!(idle.span(), None);
    assert_eq!(idle.deadline(0), None);
    assert_eq!(idle.deadline(u64::MAX), None);
    assert!(!idle.expired(u64::MAX, 5));
}

#[test]
fn sole() {
    assert_eq!(Idle::new(0, 30, 0).span(), Some(30_000));
    assert_eq!(Idle::new(0, 0, 45).span(), Some(45_000));
}

#[test]
fn lesser() {
    assert_eq!(Idle::new(0, 10, 30).span(), Some(10_000));
    assert_eq!(Idle::new(0, 30, 10).span(), Some(10_000));
    assert_eq!(Idle::new(0, 7, 7).span(), Some(7_000));
}

#[test]
fn millis() {
    assert_eq!(Idle::new(0, 1, 1).span(), Some(1_000));
    assert_eq!(Idle::new(0, 7, 0).span(), Some(7_000));
    assert_eq!(Idle::new(0, 0, 1).span(), Some(1_000));
}

#[test]
fn deadline() {
    assert_eq!(Idle::new(0, 10, 10).deadline(0), Some(10_000));
    assert_eq!(Idle::new(1_000, 10, 10).deadline(0), Some(11_000));
    assert_eq!(Idle::new(250, 0, 3).deadline(0), Some(3_250));
}

#[test]
fn floor() {
    let idle = Idle::new(0, 10, 10);
    assert_eq!(idle.deadline(3_000), Some(10_000));
    assert_eq!(idle.deadline(3_333), Some(10_000));
    assert_eq!(idle.deadline(3_334), Some(10_002));
    assert_eq!(idle.deadline(4_000), Some(12_000));
    assert_eq!(idle.deadline(10_000), Some(30_000));
    assert_eq!(Idle::new(500, 10, 10).deadline(4_000), Some(12_500));
}

#[test]
fn receive() {
    let mut idle = Idle::new(0, 10, 10);
    idle.receive(500);
    assert_eq!(idle.deadline(0), Some(10_500));
    idle.receive(2_000);
    assert_eq!(idle.deadline(0), Some(12_000));
}

#[test]
fn send() {
    let mut idle = Idle::new(0, 10, 10);
    idle.send(200, true);
    assert_eq!(idle.deadline(0), Some(10_200));
    idle.send(300, true);
    assert_eq!(idle.deadline(0), Some(10_200));
    idle.send(400, false);
    assert_eq!(idle.deadline(0), Some(10_200));
    idle.receive(1_000);
    assert_eq!(idle.deadline(0), Some(11_000));
    idle.send(1_500, true);
    assert_eq!(idle.deadline(0), Some(11_500));
    idle.send(1_600, true);
    assert_eq!(idle.deadline(0), Some(11_500));
}

#[test]
fn quiet() {
    let mut idle = Idle::new(0, 10, 10);
    idle.send(50, false);
    idle.send(60, false);
    assert_eq!(idle.deadline(0), Some(10_000));
    idle.receive(100);
    idle.send(150, false);
    assert_eq!(idle.deadline(0), Some(10_100));
    idle.send(200, true);
    assert_eq!(idle.deadline(0), Some(10_200));
}

#[test]
fn expired() {
    let idle = Idle::new(0, 10, 10);
    assert!(!idle.expired(9_999, 0));
    assert!(idle.expired(10_000, 0));
    assert!(idle.expired(10_001, 0));
    assert!(!idle.expired(11_999, 4_000));
    assert!(idle.expired(12_000, 4_000));
}

#[test]
fn saturate() {
    let idle = Idle::new(u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(idle.span(), Some(u64::MAX));
    assert_eq!(idle.deadline(u64::MAX), Some(u64::MAX));
    assert_eq!(Idle::new(u64::MAX, 1, 1).deadline(0), Some(u64::MAX));
    assert_eq!(Idle::new(0, 10, 10).deadline(u64::MAX), Some(u64::MAX));
}
