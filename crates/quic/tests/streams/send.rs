use crate::support::{piece, pull};
use quic::{Sending, Stage};

#[test]
fn ready() {
    let mut sending = Sending::new(100);
    assert_eq!(sending.stage(), Stage::Ready);
    assert_eq!(sending.next(10), None);
    assert_eq!(sending.sent(), 0);
    assert_eq!(sending.written(), 0);
    assert_eq!(sending.limit(), 100);
    assert_eq!(sending.buffered(), 0);
    assert_eq!(sending.blocked(), None);
}

#[test]
fn write() {
    let mut sending = Sending::new(100);
    assert_eq!(sending.write(b"abc"), 3);
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.written(), 3);
    assert_eq!(sending.buffered(), 3);
    assert_eq!(sending.write(b"de"), 2);
    assert_eq!(sending.written(), 5);
    assert_eq!(sending.write(b""), 0);
}

#[test]
fn order() {
    let mut sending = Sending::new(100);
    sending.write(b"0123456789");
    assert_eq!(sending.next(4), Some(piece(0, b"0123", false)));
    assert_eq!(sending.next(4), Some(piece(4, b"4567", false)));
    assert_eq!(sending.next(4), Some(piece(8, b"89", false)));
    assert_eq!(sending.next(4), None);
    assert_eq!(sending.sent(), 10);
    assert_eq!(sending.stage(), Stage::Send);
}

#[test]
fn tail() {
    let mut sending = Sending::new(100);
    sending.write(b"abcdef");
    assert!(sending.finish());
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.next(10), Some(piece(0, b"abcdef", true)));
    assert_eq!(sending.stage(), Stage::Sent);
    assert_eq!(sending.next(10), None);
}

#[test]
fn split() {
    let mut sending = Sending::new(100);
    sending.write(b"abcdef");
    sending.finish();
    assert_eq!(sending.next(4), Some(piece(0, b"abcd", false)));
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.next(4), Some(piece(4, b"ef", true)));
    assert_eq!(sending.stage(), Stage::Sent);
}

#[test]
fn lone() {
    let mut sending = Sending::new(100);
    sending.write(b"abcdef");
    assert_eq!(sending.next(10), Some(piece(0, b"abcdef", false)));
    assert_eq!(sending.next(10), None);
    assert!(sending.finish());
    assert_eq!(sending.next(10), Some(piece(6, b"", true)));
    assert_eq!(sending.stage(), Stage::Sent);
    assert_eq!(sending.next(10), None);
}

#[test]
fn empty() {
    let mut sending = Sending::new(0);
    assert!(sending.finish());
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.next(0), Some(piece(0, b"", true)));
    assert_eq!(sending.stage(), Stage::Sent);
    sending.acked(0, 0, true);
    assert_eq!(sending.stage(), Stage::Acked);
}

#[test]
fn zero() {
    let mut sending = Sending::new(100);
    sending.write(b"abc");
    assert_eq!(sending.next(0), None);
    sending.finish();
    assert_eq!(sending.next(0), None);
    assert_eq!(sending.next(3), Some(piece(0, b"abc", true)));
    let mut sending = Sending::new(100);
    sending.write(b"abc");
    sending.finish();
    assert_eq!(sending.next(3), Some(piece(0, b"abc", true)));
    let mut sending = Sending::new(100);
    sending.write(b"abc");
    assert!(sending.next(3).is_some());
    sending.finish();
    assert_eq!(sending.next(0), Some(piece(3, b"", true)));
}

#[test]
fn limit() {
    let mut sending = Sending::new(5);
    sending.write(b"abcdefghijkl");
    sending.finish();
    assert_eq!(sending.next(100), Some(piece(0, b"abcde", false)));
    assert_eq!(sending.next(100), None);
    assert_eq!(sending.stage(), Stage::Send);
    assert!(sending.raise(8));
    assert_eq!(sending.next(100), Some(piece(5, b"fgh", false)));
    assert!(sending.raise(100));
    assert_eq!(sending.next(100), Some(piece(8, b"ijkl", true)));
    assert_eq!(pull(&mut sending, 100), vec![]);
}

#[test]
fn raise() {
    let mut sending = Sending::new(5);
    assert!(!sending.raise(5));
    assert!(!sending.raise(4));
    assert_eq!(sending.limit(), 5);
    assert!(sending.raise(6));
    assert_eq!(sending.limit(), 6);
}

#[test]
fn blocked() {
    let mut sending = Sending::new(4);
    sending.write(b"0123456789");
    assert_eq!(sending.blocked(), None);
    assert!(sending.next(100).is_some());
    assert_eq!(sending.blocked(), Some(4));
    assert_eq!(sending.blocked(), None);
    assert!(!sending.raise(4));
    assert_eq!(sending.blocked(), None);
    assert!(sending.raise(8));
    assert_eq!(sending.blocked(), None);
    assert!(sending.next(100).is_some());
    assert_eq!(sending.blocked(), Some(8));
    assert_eq!(sending.blocked(), None);
    sending.raise(100);
    assert!(sending.next(100).is_some());
    assert_eq!(sending.blocked(), None);
}

#[test]
fn idle() {
    let mut sending = Sending::new(4);
    sending.write(b"0123");
    assert!(sending.next(100).is_some());
    assert_eq!(sending.blocked(), None);
}

#[test]
fn refused() {
    let mut sending = Sending::new(100);
    sending.write(b"abc");
    assert!(sending.finish());
    assert!(!sending.finish());
    assert_eq!(sending.write(b"more"), 0);
    assert_eq!(sending.written(), 3);
    let mut sending = Sending::new(100);
    assert!(sending.reset(1));
    assert_eq!(sending.write(b"x"), 0);
    assert!(!sending.finish());
    assert_eq!(sending.written(), 0);
}

#[test]
fn holdback() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    assert_eq!(sending.next(10), Some(piece(0, b"abcd", true)));
    sending.lost(0, 4, true);
    assert_eq!(sending.next(0), None);
    assert_eq!(sending.next(10), Some(piece(0, b"abcd", true)));
}

#[test]
fn late() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(10);
    sending.acked(0, 4, true);
    assert_eq!(sending.stage(), Stage::Acked);
    sending.lost(0, 4, true);
    assert_eq!(sending.stage(), Stage::Acked);
    assert_eq!(sending.next(10), None);
}

#[test]
fn apart() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    assert_eq!(sending.next(2), Some(piece(0, b"ab", false)));
    assert_eq!(sending.next(2), Some(piece(2, b"cd", true)));
    sending.lost(0, 2, false);
    assert_eq!(sending.next(10), Some(piece(0, b"ab", false)));
    assert_eq!(sending.next(10), None);
}
