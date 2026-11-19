use crate::support::token;
use quic::{Error, MINIMUM, Path, Validity};

const FRESH: u64 = 999_000;

fn pending(at: u64) -> Path {
    let mut path = Path::new(0);
    path.challenge(at, token(1), u64::MAX).unwrap();
    path
}

#[test]
fn timeout() {
    assert_eq!(Path::new(0).timeout(), 2_997_000);
    assert_eq!(Path::new(500_000).timeout(), 2_997_000);
    assert_eq!(Path::new(FRESH).timeout(), 2_997_000);
    assert_eq!(Path::new(FRESH + 1).timeout(), 2_997_003);
    assert_eq!(Path::new(1_000_000).timeout(), 3_000_000);
    assert_eq!(Path::new(u64::MAX).timeout(), u64::MAX);
}

#[test]
fn expand() {
    for (room, expected) in [
        (0, false),
        (MINIMUM - 1, false),
        (MINIMUM, true),
        (u64::MAX, true),
    ] {
        let mut path = Path::new(0);
        let probe = path.challenge(0, token(7), room).unwrap();
        assert_eq!(probe.expand, expected, "room {room}");
        assert_eq!(probe.token, token(7));
    }
    assert_eq!(MINIMUM, 1200);
}

#[test]
fn idle() {
    let mut path = Path::new(0);
    assert_eq!(path.validity(), Validity::Idle);
    assert_eq!(path.deadline(), None);
    assert!(!path.mtu());
    assert!(!path.response(token(1)));
    assert_eq!(path.validity(), Validity::Idle);
}

#[test]
fn begin() {
    let mut path = Path::new(0);
    path.challenge(100, token(1), u64::MAX).unwrap();
    assert_eq!(path.validity(), Validity::Pending);
    assert_eq!(path.deadline(), Some(100 + 2_997_000));
    path.challenge(500, token(2), u64::MAX).unwrap();
    assert_eq!(path.deadline(), Some(100 + 2_997_000));
    assert_eq!(path.validity(), Validity::Pending);
}

#[test]
fn accept() {
    let mut path = pending(10);
    assert!(path.response(token(1)));
    assert_eq!(path.validity(), Validity::Valid);
    assert_eq!(path.deadline(), None);
    assert!(path.mtu());
}

#[test]
fn unmatched() {
    let mut path = pending(10);
    assert!(!path.response(token(2)));
    assert_eq!(path.validity(), Validity::Pending);
    assert_eq!(path.deadline(), Some(10 + 2_997_000));
    assert!(!path.mtu());
    assert!(path.response(token(1)));
}

#[test]
fn either() {
    let mut path = pending(0);
    path.challenge(1, token(2), u64::MAX).unwrap();
    assert!(path.response(token(2)));
    assert_eq!(path.validity(), Validity::Valid);
    assert!(!path.response(token(1)));
    assert_eq!(path.validity(), Validity::Valid);
}

#[test]
fn duplicate() {
    let mut path = pending(0);
    assert_eq!(path.challenge(1, token(1), u64::MAX), Err(Error::Duplicate));
    assert_eq!(path.validity(), Validity::Pending);
    assert_eq!(path.deadline(), Some(2_997_000));
    assert!(path.response(token(1)));
}

#[test]
fn capped() {
    let mut path = Path::new(0);
    for seed in 0..8 {
        path.challenge(seed, token(seed + 10), u64::MAX).unwrap();
    }
    assert_eq!(path.challenge(9, token(99), u64::MAX), Err(Error::Value));
    assert_eq!(path.validity(), Validity::Pending);
    assert!(path.response(token(17)));
    assert!(!path.response(token(99)));
    path.challenge(10, token(99), u64::MAX).unwrap();
    assert!(path.response(token(99)));
}

#[test]
fn expiry() {
    let mut path = pending(1000);
    let due = 1000 + 2_997_000;
    assert!(!path.expire(due - 1));
    assert_eq!(path.validity(), Validity::Pending);
    assert_eq!(path.deadline(), Some(due));
    assert!(path.expire(due));
    assert_eq!(path.validity(), Validity::Failed);
    assert_eq!(path.deadline(), None);
    assert!(!path.expire(due + 1));
}

#[test]
fn late() {
    let mut path = pending(0);
    assert!(path.expire(u64::MAX));
    assert!(!path.response(token(1)));
    assert_eq!(path.validity(), Validity::Failed);
    assert_eq!(path.challenge(0, token(5), u64::MAX), Err(Error::Value));
    assert_eq!(path.validity(), Validity::Failed);
}

#[test]
fn settled() {
    let mut path = pending(0);
    assert!(path.response(token(1)));
    assert!(!path.expire(u64::MAX));
    assert_eq!(path.validity(), Validity::Valid);
}

#[test]
fn quiet() {
    let mut path = Path::new(0);
    assert!(!path.expire(u64::MAX));
    assert_eq!(path.validity(), Validity::Idle);
}

#[test]
fn abandon() {
    let mut path = Path::new(0);
    path.abandon();
    assert_eq!(path.validity(), Validity::Idle);
    let mut path = pending(0);
    path.abandon();
    assert_eq!(path.validity(), Validity::Failed);
    assert_eq!(path.deadline(), None);
    assert!(!path.response(token(1)));
    path.abandon();
    assert_eq!(path.validity(), Validity::Failed);
    let mut path = pending(0);
    assert!(path.response(token(1)));
    path.abandon();
    assert_eq!(path.validity(), Validity::Valid);
}

#[test]
fn small() {
    let mut path = Path::new(0);
    path.challenge(0, token(1), MINIMUM - 1).unwrap();
    assert!(path.response(token(1)));
    assert_eq!(path.validity(), Validity::Valid);
    assert!(!path.mtu());
    path.challenge(50, token(2), MINIMUM).unwrap();
    assert_eq!(path.validity(), Validity::Pending);
    assert!(!path.mtu());
    assert!(path.response(token(2)));
    assert_eq!(path.validity(), Validity::Valid);
    assert!(path.mtu());
}

#[test]
fn sticky() {
    let mut path = pending(0);
    assert!(path.response(token(1)));
    assert!(path.mtu());
    path.challenge(10, token(2), 0).unwrap();
    assert_eq!(path.validity(), Validity::Pending);
    assert!(path.mtu());
    assert!(path.response(token(2)));
    assert!(path.mtu());
}

#[test]
fn mixed() {
    let mut path = Path::new(0);
    path.challenge(0, token(1), 0).unwrap();
    path.challenge(1, token(2), u64::MAX).unwrap();
    assert!(path.response(token(1)));
    assert!(!path.mtu());
    let mut path = Path::new(0);
    path.challenge(0, token(1), 0).unwrap();
    path.challenge(1, token(2), u64::MAX).unwrap();
    assert!(path.response(token(2)));
    assert!(path.mtu());
}

#[test]
fn restart() {
    let mut path = pending(0);
    assert!(path.response(token(1)));
    path.challenge(5000, token(1), u64::MAX).unwrap();
    assert_eq!(path.validity(), Validity::Pending);
    assert_eq!(path.deadline(), Some(5000 + 2_997_000));
    assert!(!path.expire(5000 + 2_996_999));
    assert!(path.expire(5000 + 2_997_000));
    assert_eq!(path.validity(), Validity::Failed);
}

#[test]
fn stale() {
    let mut path = pending(0);
    assert!(path.response(token(1)));
    path.challenge(10, token(2), u64::MAX).unwrap();
    assert!(!path.response(token(1)));
    assert_eq!(path.validity(), Validity::Pending);
}

#[test]
fn saturate() {
    let mut path = Path::new(u64::MAX);
    path.challenge(u64::MAX, token(1), 0).unwrap();
    assert_eq!(path.deadline(), Some(u64::MAX));
    assert!(path.expire(u64::MAX));
}
