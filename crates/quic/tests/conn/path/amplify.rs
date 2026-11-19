use quic::Amplify;

#[test]
fn fresh() {
    let amplify = Amplify::new(false);
    assert_eq!(amplify.room(), 0);
    assert!(amplify.blocked());
    assert!(!amplify.validated());
}

#[test]
fn triple() {
    let mut amplify = Amplify::new(false);
    amplify.receive(1200);
    assert_eq!(amplify.room(), 3600);
    assert!(!amplify.blocked());
    assert!(amplify.send(3600));
    assert_eq!(amplify.room(), 0);
    assert!(amplify.blocked());
    assert!(!amplify.send(1));
}

#[test]
fn refused() {
    let mut amplify = Amplify::new(false);
    amplify.receive(1000);
    assert!(!amplify.send(3001));
    assert_eq!(amplify.room(), 3000);
    assert!(amplify.send(3000));
    assert_eq!(amplify.room(), 0);
}

#[test]
fn edge() {
    let mut amplify = Amplify::new(false);
    amplify.receive(1200);
    assert!(amplify.send(1));
    assert_eq!(amplify.room(), 3599);
    assert!(!amplify.send(3600));
    assert_eq!(amplify.room(), 3599);
    assert!(amplify.send(3599));
    assert!(amplify.blocked());
}

#[test]
fn accrue() {
    let mut amplify = Amplify::new(false);
    amplify.receive(100);
    assert!(amplify.send(200));
    assert_eq!(amplify.room(), 100);
    amplify.receive(100);
    assert_eq!(amplify.room(), 400);
    amplify.receive(0);
    assert_eq!(amplify.room(), 400);
}

#[test]
fn validate() {
    let mut amplify = Amplify::new(false);
    amplify.receive(10);
    assert!(amplify.send(30));
    assert!(amplify.blocked());
    amplify.validate();
    assert!(amplify.validated());
    assert!(!amplify.blocked());
    assert_eq!(amplify.room(), u64::MAX);
    assert!(amplify.send(u64::MAX));
    assert_eq!(amplify.room(), u64::MAX);
}

#[test]
fn client() {
    let mut amplify = Amplify::new(true);
    assert!(amplify.validated());
    assert!(!amplify.blocked());
    assert_eq!(amplify.room(), u64::MAX);
    assert!(amplify.send(1_000_000));
    assert!(!amplify.blocked());
}

#[test]
fn saturate() {
    let mut amplify = Amplify::new(false);
    amplify.receive(u64::MAX);
    assert_eq!(amplify.room(), u64::MAX);
    assert!(amplify.send(u64::MAX));
    assert_eq!(amplify.room(), 0);
    amplify.receive(u64::MAX);
    assert_eq!(amplify.room(), 0);
    assert!(!amplify.send(1));
    let mut amplify = Amplify::new(false);
    amplify.receive(u64::MAX);
    amplify.receive(1);
    assert_eq!(amplify.room(), u64::MAX);
}

#[test]
fn zero() {
    let mut amplify = Amplify::new(false);
    assert!(amplify.send(0));
    assert_eq!(amplify.room(), 0);
    amplify.receive(0);
    assert!(amplify.blocked());
    assert!(!amplify.send(1));
}

#[test]
fn copies() {
    let mut amplify = Amplify::new(false);
    amplify.receive(500);
    let copy = amplify.clone();
    assert!(amplify.send(1500));
    assert_eq!(copy.room(), 1500);
    assert_eq!(amplify.room(), 0);
    assert_ne!(copy, amplify);
}
