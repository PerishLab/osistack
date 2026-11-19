use crate::support::*;
use quic::{Direction, Error, Param, Params, Side};

#[test]
fn lengths() {
    fails("01 02 05 00", Error::Length);
    fails("01 00", Error::Length);
    fails("01 01 40", Error::Length);
    fails("04 05 80000001 00", Error::Length);
    fails("0e 03 02 00 00", Error::Length);
}

#[test]
fn payload() {
    fails("03 02 44af", Error::Value);
    fails("03 01 00", Error::Value);
    assert!(Params::parse(&hex("03 02 44b0")).is_ok());
}

#[test]
fn streams() {
    fails("08 08 d000000000000001", Error::Value);
    fails("09 08 d000000000000001", Error::Value);
    fails("08 08 ffffffffffffffff", Error::Value);
    assert!(Params::parse(&hex("09 08 d000000000000000")).is_ok());
}

#[test]
fn exponent() {
    fails("0a 01 15", Error::Value);
    assert!(Params::parse(&hex("0a 01 14")).is_ok());
}

#[test]
fn delay() {
    fails("0b 04 80004000", Error::Value);
    assert!(Params::parse(&hex("0b 02 7fff")).is_ok());
}

#[test]
fn limit() {
    fails("0e 01 01", Error::Value);
    fails("0e 01 00", Error::Value);
    assert!(Params::parse(&hex("0e 01 02")).is_ok());
}

#[test]
fn reset() {
    fails(&format!("02 0f {}", &TOKEN[..30]), Error::Length);
    fails(&format!("02 11 {TOKEN}00"), Error::Length);
    fails("02 00", Error::Length);
}

#[test]
fn migration() {
    fails("0c 01 00", Error::Length);
}

#[test]
fn identifiers() {
    let over = "ab".repeat(21);
    for id in ["00", "0f", "10"] {
        fails(&format!("{id} 15 {over}"), Error::Length);
    }
}

#[test]
fn addresses() {
    let head = format!("7f000001 1f90 {} 1f91", "00".repeat(16));
    fails(&format!("0d 29 {head} 00 {TOKEN}"), Error::Length);
    let over = "aa".repeat(21);
    fails(&format!("0d 3e {head} 15 {over} {TOKEN}"), Error::Length);
    fails(&format!("0d 2b {head} 01 aa {TOKEN} 00"), Error::Length);
    fails(&format!("0d 29 {head} 01 aa {}", &TOKEN[..30]), cut());
    fails("0d 00", cut());
}

#[test]
fn duplicates() {
    fails("01 01 05 01 01 06", Error::Duplicate);
    fails("0c 00 0c 00", Error::Duplicate);
    fails("1b 00 1b 01 aa", Error::Duplicate);
    fails("01 01 05 04 01 05 01 01 05", Error::Duplicate);
    fails("4078 00 4078 00", Error::Duplicate);
}

#[test]
fn huge() {
    fails("01 ffffffffffffffff", cut());
    fails("1b ffffffffffffffff aa", cut());
}

#[test]
fn prefixes() {
    let texts = [
        "00 08 8394c8f03e515708",
        "01 04 80007530",
        &format!("02 10 {TOKEN}"),
        "03 02 44b0",
        "04 08 d000000000000000",
        "05 02 4400",
        "08 01 10",
        "0a 01 14",
        "0b 02 7fff",
        "0c 00",
        "0e 01 02",
        "0f 04 01020304",
        "4078 03 010203",
        &format!(
            "0d 2d 7f000001 1f90 {} 1f91 04 aabbccdd {TOKEN}",
            "00".repeat(16)
        ),
    ];
    for text in texts {
        let bytes = hex(text);
        assert!(Params::parse(&bytes).is_ok(), "{text}");
        for size in 1..bytes.len() {
            assert_eq!(Params::parse(&bytes[..size]), Err(cut()), "{text} {size}");
        }
    }
}

#[test]
fn boundaries() {
    let bytes = hex("04 01 05 01 01 06 0c 00");
    let found: Vec<usize> = (0..=bytes.len())
        .filter(|size| Params::parse(&bytes[..*size]).is_ok())
        .collect();
    assert_eq!(found, vec![0, 3, 6, 8]);
}

#[test]
fn writing() {
    let id = vec![1u8; 21];
    assert_eq!(write(vec![Param::Payload(1199)]), Err(Error::Value));
    assert!(write(vec![Param::Payload(1200)]).is_ok());
    assert_eq!(write(vec![Param::Exponent(21)]), Err(Error::Value));
    assert_eq!(write(vec![Param::Delay(16384)]), Err(Error::Value));
    assert_eq!(write(vec![Param::Limit(1)]), Err(Error::Value));
    let over = (1 << 60) + 1;
    for kind in [Direction::Bidi, Direction::Uni] {
        assert_eq!(write(vec![Param::Streams(kind, over)]), Err(Error::Value));
    }
    assert_eq!(write(vec![Param::Original(id.clone())]), Err(Error::Length));
    assert_eq!(write(vec![Param::Source(id.clone())]), Err(Error::Length));
    assert_eq!(write(vec![Param::Retry(id)]), Err(Error::Length));
    assert_eq!(
        write(vec![Param::Address(address(&[]))]),
        Err(Error::Length)
    );
    assert_eq!(
        write(vec![Param::Address(address(&[7; 21]))]),
        Err(Error::Length)
    );
    let range = Error::Wire(wire::Error::Range);
    assert_eq!(write(vec![Param::Idle(1 << 62)]), Err(range));
    assert_eq!(write(vec![Param::Window(Side::Local, 1 << 62)]), Err(range));
}

#[test]
fn repeating() {
    let twice = vec![Param::Idle(1), Param::Idle(2)];
    assert_eq!(write(twice), Err(Error::Duplicate));
    let other = vec![Param::Other(30, vec![]), Param::Other(30, vec![1])];
    assert_eq!(write(other), Err(Error::Duplicate));
    let sides = vec![Param::Window(Side::Local, 1), Param::Window(Side::Local, 2)];
    assert_eq!(write(sides), Err(Error::Duplicate));
}

#[test]
fn known() {
    assert_eq!(write(vec![Param::Other(1, vec![5])]), Err(Error::Kind));
    assert_eq!(write(vec![Param::Other(0x10, vec![])]), Err(Error::Kind));
    assert!(write(vec![Param::Other(0x11, vec![])]).is_ok());
}
