use crate::support::piece;
use quic::{Sending, Stage};

#[test]
fn abort() {
    let mut sending = Sending::new(100);
    sending.write(b"0123456789");
    sending.next(6);
    assert!(sending.reset(7));
    assert_eq!(sending.stage(), Stage::Reset);
    assert_eq!(sending.frame(), Some((7, 6)));
    assert_eq!(sending.frame(), None);
    assert_eq!(sending.next(100), None);
    assert_eq!(sending.buffered(), 0);
    assert_eq!(sending.write(b"x"), 0);
}

#[test]
fn ready() {
    let mut sending = Sending::new(100);
    assert!(sending.reset(1));
    assert_eq!(sending.frame(), Some((1, 0)));
}

#[test]
fn fin() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(100);
    assert_eq!(sending.stage(), Stage::Sent);
    assert!(sending.reset(2));
    assert_eq!(sending.stage(), Stage::Reset);
    assert_eq!(sending.frame(), Some((2, 4)));
}

#[test]
fn acked() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(100);
    sending.acked(0, 4, true);
    assert_eq!(sending.stage(), Stage::Acked);
    assert!(!sending.reset(3));
    assert!(!sending.stop(3));
    assert_eq!(sending.stage(), Stage::Acked);
    assert_eq!(sending.frame(), None);
}

#[test]
fn twice() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.next(2);
    assert!(sending.reset(5));
    assert!(!sending.reset(6));
    assert!(!sending.stop(7));
    assert_eq!(sending.frame(), Some((5, 2)));
}

#[test]
fn stop() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.next(3);
    assert!(sending.stop(9));
    assert_eq!(sending.stage(), Stage::Reset);
    assert!(!sending.stop(10));
    assert_eq!(sending.frame(), Some((9, 3)));
}

#[test]
fn cycle() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.next(4);
    sending.reset(4);
    assert_eq!(sending.frame(), Some((4, 4)));
    assert_eq!(sending.frame(), None);
    sending.retry();
    assert_eq!(sending.frame(), Some((4, 4)));
    sending.settle();
    assert_eq!(sending.stage(), Stage::Gone);
    sending.retry();
    assert_eq!(sending.frame(), None);
    assert_eq!(sending.stage(), Stage::Gone);
}

#[test]
fn quiet() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.retry();
    sending.settle();
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.next(10), Some(piece(0, b"abcd", false)));
}

#[test]
fn early() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.reset(1);
    sending.retry();
    assert_eq!(sending.frame(), Some((1, 0)));
    sending.retry();
    sending.settle();
    assert_eq!(sending.frame(), None);
    assert_eq!(sending.stage(), Stage::Gone);
}

#[test]
fn unsent() {
    let mut sending = Sending::new(100);
    sending.write(b"0123456789");
    sending.next(4);
    sending.reset(1);
    assert_eq!(sending.frame(), Some((1, 4)));
    assert_eq!(sending.sent(), 4);
}

#[test]
fn halted() {
    let mut sending = Sending::new(2);
    sending.write(b"abcdef");
    sending.next(10);
    assert_eq!(sending.blocked(), Some(2));
    sending.reset(1);
    assert!(sending.raise(10));
    assert_eq!(sending.blocked(), None);
    assert_eq!(sending.next(10), None);
}

#[test]
fn after() {
    let mut sending = Sending::new(100);
    sending.finish();
    sending.reset(1);
    assert_eq!(sending.next(10), None);
}

#[test]
fn eager() {
    let mut sending = Sending::new(100);
    sending.settle();
    assert!(sending.reset(1));
    assert_eq!(sending.stage(), Stage::Reset);
    assert_eq!(sending.frame(), Some((1, 0)));
}
