use crate::support::*;
use quic::{Direction, Error, Frame};

const MAX: &str = "ffffffffffffffff";

fn cut() -> Error {
    Error::Wire(wire::Error::Truncated)
}

#[test]
fn minimal() {
    fails("4001", Error::Minimal);
    fails("4000", Error::Minimal);
    fails("4000 00", Error::Minimal);
    fails("80000001", Error::Minimal);
    fails("c000000000000001", Error::Minimal);
}

#[test]
fn unknown() {
    for text in ["1f", "20", "2f", "3f", "4040", "7fff", "bfffffff"] {
        fails(text, Error::Kind);
    }
}

#[test]
fn datagram() {
    fails("30 aa", Error::Excluded);
    fails("31 01 aa", Error::Excluded);
}

#[test]
fn empty() {
    assert_eq!(Frame::parse(&[]), Err(cut()));
    assert_eq!(Frame::all(&[]), Ok(vec![]));
}

#[test]
fn largest() {
    fails("02 05 00 00 06", Error::Value);
    fails("03 05 00 00 06 00 00 00", Error::Value);
    assert!(Frame::parse(&hex("02 05 00 00 05")).is_ok());
}

#[test]
fn gap() {
    fails("02 05 00 01 00 04 00", Error::Value);
    fails("02 05 00 01 00 03 01", Error::Value);
    assert!(Frame::parse(&hex("02 05 00 01 00 03 00")).is_ok());
}

#[test]
fn length() {
    fails("02 05 00 01 00 00 04", Error::Value);
    assert!(Frame::parse(&hex("02 05 00 01 00 00 03")).is_ok());
}

#[test]
fn later() {
    fails("02 14 00 02 03 01 02 00 0b", Error::Value);
    assert!(Frame::parse(&hex("02 14 00 02 03 01 02 00 0a")).is_ok());
}

#[test]
fn count() {
    fails(&format!("02 05 00 {MAX} 00"), cut());
    fails(&format!("02 05 00 {MAX} 00 00 00"), cut());
}

#[test]
fn streams() {
    for code in ["12", "13", "16", "17"] {
        fails(&format!("{code} d000000000000001"), Error::Value);
        fails(&format!("{code} {MAX}"), Error::Value);
        assert!(Frame::parse(&hex(&format!("{code} d000000000000000"))).is_ok());
    }
}

#[test]
fn offsets() {
    fails(&format!("06 {MAX} 01 aa"), Error::Value);
    assert!(Frame::parse(&hex(&format!("06 {MAX} 00"))).is_ok());
    fails(&format!("0e 00 {MAX} 01 aa"), Error::Value);
    fails(&format!("0c 00 {MAX} aa"), Error::Value);
    assert!(Frame::parse(&hex(&format!("0e 00 {MAX} 00"))).is_ok());
    assert!(Frame::parse(&hex(&format!("0c 00 {MAX}"))).is_ok());
}

#[test]
fn blank() {
    fails("07 00", Error::Empty);
}

#[test]
fn identifiers() {
    fails(&format!("18 00 00 00 {TOKEN}"), Error::Length);
    fails(
        &format!("18 01 00 15 {} {TOKEN}", "aa".repeat(21)),
        Error::Length,
    );
    fails(&format!("18 01 02 01 aa {TOKEN}"), Error::Value);
    assert!(Frame::parse(&hex(&format!("18 01 01 01 aa {TOKEN}"))).is_ok());
}

#[test]
fn lengths() {
    fails("0a 04 05 616263", cut());
    fails(&format!("0a 04 {MAX}"), cut());
    fails(&format!("06 00 {MAX}"), cut());
    fails(&format!("07 {MAX}"), cut());
    fails(&format!("1c 00 00 {MAX}"), cut());
    fails(&format!("1d 00 {MAX}"), cut());
}

#[test]
fn prefixes() {
    let frames = [
        "02 05 412c 00 00",
        "02 14 00 02 03 01 02 00 01",
        "03 14 00 01 03 01 02 05 06 07",
        "04 01 02 03",
        "05 04 07",
        "06 05 03 616263",
        "07 02 aabb",
        "0a 04 03 616263",
        "0f 04 02 03 616263",
        "10 40ff",
        "11 04 4400",
        "12 10",
        "13 10",
        "14 2a",
        "15 04 2a",
        "16 10",
        "17 10",
        &format!("18 02 01 04 01020304 {TOKEN}"),
        "19 03",
        "1a 0102030405060708",
        "1b 0807060504030201",
        "1c 0a 06 03 616263",
        "1d 0b 02 6869",
        "12 d000000000000000",
    ];
    for text in frames {
        let bytes = hex(text);
        assert!(Frame::parse(&bytes).is_ok(), "{text}");
        for size in 0..bytes.len() {
            assert_eq!(Frame::parse(&bytes[..size]), Err(cut()), "{text} {size}");
        }
    }
}

#[test]
fn open() {
    let bytes = hex("08 04 616263");
    for size in 2..bytes.len() {
        assert!(Frame::parse(&bytes[..size]).is_ok());
    }
    for size in 0..2 {
        assert_eq!(Frame::parse(&bytes[..size]), Err(cut()));
    }
    let offset = hex("0d 04 02 616263");
    for size in 0..3 {
        assert_eq!(Frame::parse(&offset[..size]), Err(cut()));
    }
    for size in 3..=offset.len() {
        assert!(Frame::parse(&offset[..size]).is_ok());
    }
}

#[test]
fn joining() {
    let open = stream(4, 0, b"a", (false, false));
    assert_eq!(Frame::join(&[open.clone(), Frame::Ping]), Err(Error::Value));
    assert_eq!(
        Frame::join(&[Frame::Ping, open]).unwrap(),
        hex("01 08 04 61")
    );
    assert_eq!(Frame::join(&[Frame::Padding(0)]), Err(Error::Value));
    assert_eq!(Frame::Padding(0).write(), Err(Error::Value));
}

#[test]
fn writing() {
    let bad = |frame: Frame, error: Error| assert_eq!(frame.write(), Err(error), "{frame:?}");
    let big = (1 << 60) + 1;
    for kind in [Direction::Bidi, Direction::Uni] {
        bad(Frame::Streams { kind, limit: big }, Error::Value);
        bad(Frame::Choked { kind, limit: big }, Error::Value);
    }
    bad(Frame::Token(vec![]), Error::Empty);
    bad(Frame::Ack(ack(5, 0, 6, &[])), Error::Value);
    bad(Frame::Ack(ack(5, 0, 0, &[(4, 0)])), Error::Value);
    bad(Frame::Ack(ack(5, 0, 0, &[(0, 4)])), Error::Value);
    let crypto = Frame::Crypto {
        offset: (1 << 62) - 1,
        data: vec![1],
    };
    bad(crypto, Error::Value);
    bad(stream(1, (1 << 62) - 1, b"a", (false, true)), Error::Value);
    let issue = |sequence, retire, size| Frame::Issue {
        sequence,
        retire,
        cid: vec![1; size],
        token: token(),
    };
    bad(issue(1, 0, 0), Error::Length);
    bad(issue(1, 0, 21), Error::Length);
    bad(issue(1, 2, 1), Error::Value);
    assert!(issue(1, 1, 20).write().is_ok());
    let range = Error::Wire(wire::Error::Range);
    bad(Frame::Data(1 << 62), range);
    bad(Frame::Retire(1 << 62), range);
}
