use crate::support::{piece, pull};
use quic::{Sending, Stage};

fn sent(data: &[u8], limit: u64) -> Sending {
    let mut sending = Sending::new(limit);
    sending.write(data);
    while sending.next(1000).is_some() {}
    sending
}

#[test]
fn release() {
    let mut sending = sent(b"0123456789", 100);
    sending.acked(0, 4, false);
    assert_eq!(sending.buffered(), 6);
    sending.acked(6, 4, false);
    assert_eq!(sending.buffered(), 6);
    sending.acked(4, 2, false);
    assert_eq!(sending.buffered(), 0);
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.written(), 10);
}

#[test]
fn redo() {
    let mut sending = sent(b"0123456789", 100);
    sending.lost(2, 3, false);
    assert_eq!(sending.next(100), Some(piece(2, b"234", false)));
    assert_eq!(sending.next(100), None);
}

#[test]
fn chop() {
    let mut sending = sent(b"0123456789", 100);
    sending.lost(0, 10, false);
    assert_eq!(
        pull(&mut sending, 4),
        vec![
            piece(0, b"0123", false),
            piece(4, b"4567", false),
            piece(8, b"89", false)
        ]
    );
}

#[test]
fn first() {
    let mut sending = Sending::new(100);
    sending.write(b"0123456789");
    assert_eq!(sending.next(5), Some(piece(0, b"01234", false)));
    sending.lost(1, 2, false);
    assert_eq!(sending.next(100), Some(piece(1, b"12", false)));
    assert_eq!(sending.next(100), Some(piece(5, b"56789", false)));
}

#[test]
fn cut() {
    let mut sending = sent(b"0123456789", 100);
    sending.lost(0, 10, false);
    sending.acked(3, 4, false);
    assert_eq!(
        pull(&mut sending, 100),
        vec![piece(0, b"012", false), piece(7, b"789", false)]
    );
}

#[test]
fn clamp() {
    let mut sending = sent(b"0123456789", 100);
    sending.acked(8, 100, false);
    assert_eq!(sending.buffered(), 10);
    sending.lost(5, 100, false);
    assert_eq!(pull(&mut sending, 100), vec![piece(5, b"567", false)]);
    sending.acked(5, 3, false);
    sending.acked(0, 5, false);
    assert_eq!(sending.buffered(), 0);
    let mut sending = sent(b"0123456789", 100);
    sending.lost(100, 5, false);
    assert_eq!(sending.next(100), None);
    sending.acked(100, 5, false);
    assert_eq!(sending.buffered(), 10);
}

#[test]
fn merge() {
    let mut sending = sent(b"0123456789", 100);
    sending.acked(0, 3, false);
    sending.acked(5, 3, false);
    assert_eq!(sending.buffered(), 7);
    sending.acked(3, 2, false);
    assert_eq!(sending.buffered(), 2);
    sending.acked(6, 3, false);
    assert_eq!(sending.buffered(), 1);
    sending.acked(8, 2, false);
    assert_eq!(sending.buffered(), 0);
}

#[test]
fn stale() {
    let mut sending = sent(b"0123456789", 100);
    sending.acked(0, 4, false);
    sending.acked(0, 2, false);
    assert_eq!(sending.buffered(), 6);
    sending.lost(0, 4, false);
    assert_eq!(sending.next(100), None);
    sending.lost(2, 4, false);
    assert_eq!(sending.next(100), Some(piece(4, b"45", false)));
}

#[test]
fn twice() {
    let mut sending = sent(b"0123456789", 100);
    sending.lost(2, 3, false);
    sending.lost(2, 3, false);
    sending.lost(3, 4, false);
    assert_eq!(pull(&mut sending, 100), vec![piece(2, b"23456", false)]);
}

#[test]
fn again() {
    let mut sending = sent(b"0123456789", 100);
    sending.lost(2, 3, false);
    assert!(sending.next(100).is_some());
    sending.lost(2, 3, false);
    assert_eq!(sending.next(100), Some(piece(2, b"234", false)));
}

#[test]
fn unsent() {
    let mut sending = Sending::new(100);
    sending.write(b"0123456789");
    assert!(sending.next(4).is_some());
    sending.lost(0, 10, false);
    assert_eq!(sending.next(100), Some(piece(0, b"0123", false)));
    assert_eq!(sending.next(100), Some(piece(4, b"456789", false)));
}

#[test]
fn beyond() {
    let mut sending = Sending::new(4);
    sending.write(b"0123456789");
    assert!(sending.next(100).is_some());
    sending.lost(0, 4, false);
    assert_eq!(sending.next(100), Some(piece(0, b"0123", false)));
    assert_eq!(sending.next(100), None);
}

#[test]
fn flagged() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    assert_eq!(sending.next(100), Some(piece(0, b"abcd", true)));
    sending.lost(0, 4, true);
    assert_eq!(sending.stage(), Stage::Sent);
    assert_eq!(sending.next(100), Some(piece(0, b"abcd", true)));
    assert_eq!(sending.next(100), None);
}

#[test]
fn apart() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(100);
    sending.acked(0, 4, false);
    sending.lost(0, 4, true);
    assert_eq!(sending.next(100), Some(piece(4, b"", true)));
    assert_eq!(sending.next(100), None);
    sending.acked(4, 0, true);
    assert_eq!(sending.stage(), Stage::Acked);
}

#[test]
fn halves() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(100);
    sending.lost(0, 4, true);
    assert_eq!(
        pull(&mut sending, 2),
        vec![piece(0, b"ab", false), piece(2, b"cd", true)]
    );
}

#[test]
fn spread() {
    let mut sending = Sending::new(100);
    sending.write(b"abcdefghijkl");
    sending.finish();
    sending.next(4);
    sending.next(4);
    sending.next(4);
    sending.lost(0, 4, false);
    sending.lost(8, 4, true);
    assert_eq!(
        pull(&mut sending, 100),
        vec![piece(0, b"abcd", false), piece(8, b"ijkl", true)]
    );
}

#[test]
fn settle() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(100);
    sending.acked(0, 2, true);
    assert_eq!(sending.stage(), Stage::Sent);
    sending.acked(2, 2, false);
    assert_eq!(sending.stage(), Stage::Acked);
    assert_eq!(sending.buffered(), 0);
}

#[test]
fn finack() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.finish();
    sending.next(100);
    sending.lost(0, 4, true);
    sending.acked(0, 4, true);
    assert_eq!(sending.stage(), Stage::Acked);
    assert_eq!(sending.next(100), None);
}

#[test]
fn early() {
    let mut sending = Sending::new(100);
    sending.write(b"abcd");
    sending.acked(0, 4, true);
    sending.lost(0, 4, true);
    sending.finish();
    assert_eq!(sending.stage(), Stage::Send);
    assert_eq!(sending.next(100), Some(piece(0, b"abcd", true)));
    assert_eq!(sending.next(100), None);
}

#[test]
fn ignored() {
    let mut sending = sent(b"0123456789", 100);
    assert!(sending.reset(1));
    sending.acked(0, 10, false);
    sending.lost(0, 10, false);
    assert_eq!(sending.next(100), None);
    assert_eq!(sending.buffered(), 0);
    assert_eq!(sending.stage(), Stage::Reset);
}

#[test]
fn point() {
    let mut sending = sent(b"0123456789", 100);
    sending.lost(0, 10, false);
    sending.acked(5, 0, false);
    sending.lost(5, 0, false);
    assert_eq!(
        pull(&mut sending, 100),
        vec![piece(0, b"0123456789", false)]
    );
}

#[test]
fn huge() {
    let mut sending = sent(b"0123456789", 100);
    sending.acked(5, u64::MAX, false);
    sending.acked(0, 5, false);
    assert_eq!(sending.buffered(), 0);
}
