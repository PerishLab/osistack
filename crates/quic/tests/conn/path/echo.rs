use crate::support::token;
use quic::{Echo, MINIMUM};

#[test]
fn reply() {
    let mut echo = Echo::default();
    assert!(echo.challenge(token(1)));
    assert_eq!(echo.pending(), 1);
    let probe = echo.next(u64::MAX).unwrap();
    assert_eq!(probe.token, token(1));
    assert!(probe.expand);
    assert_eq!(echo.pending(), 0);
    assert!(echo.next(u64::MAX).is_none());
}

#[test]
fn order() {
    let mut echo = Echo::default();
    for seed in 1..=4 {
        assert!(echo.challenge(token(seed)));
    }
    for seed in 1..=4 {
        assert_eq!(echo.next(5000).unwrap().token, token(seed));
    }
    assert!(echo.next(5000).is_none());
}

#[test]
fn twice() {
    let mut echo = Echo::default();
    assert!(echo.challenge(token(3)));
    assert!(echo.challenge(token(3)));
    assert_eq!(echo.pending(), 2);
    assert_eq!(echo.next(u64::MAX).unwrap().token, token(3));
    assert_eq!(echo.next(u64::MAX).unwrap().token, token(3));
    assert!(echo.next(u64::MAX).is_none());
}

#[test]
fn capped() {
    let mut echo = Echo::default();
    for seed in 0..8 {
        assert!(echo.challenge(token(seed)));
    }
    assert!(!echo.challenge(token(8)));
    assert_eq!(echo.pending(), 8);
    assert_eq!(echo.next(u64::MAX).unwrap().token, token(0));
    assert!(echo.challenge(token(8)));
    assert_eq!(echo.pending(), 8);
    let last = (0..8).map(|_| echo.next(u64::MAX).unwrap().token).last();
    assert_eq!(last, Some(token(8)));
}

#[test]
fn roomless() {
    let mut echo = Echo::default();
    assert!(echo.challenge(token(1)));
    assert!(echo.next(0).is_none());
    assert_eq!(echo.pending(), 1);
    let probe = echo.next(5).unwrap();
    assert_eq!(probe.token, token(1));
    assert!(!probe.expand);
}

#[test]
fn edge() {
    let mut echo = Echo::default();
    assert!(echo.challenge(token(1)));
    assert!(echo.challenge(token(2)));
    assert!(!echo.next(MINIMUM - 1).unwrap().expand);
    assert!(echo.next(MINIMUM).unwrap().expand);
}

#[test]
fn empty() {
    let mut echo = Echo::default();
    assert_eq!(echo.pending(), 0);
    assert!(echo.next(u64::MAX).is_none());
    assert!(echo.next(0).is_none());
}
