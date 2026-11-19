use quic::{Fault, Phase, Receiving};

#[test]
fn size() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(0, b"abc", true), Ok(3));
    assert_eq!(receiving.size(), Some(3));
    assert_eq!(receiving.phase(), Phase::Whole);
    assert_eq!(receiving.data(0, b"abc", true), Ok(0));
    assert_eq!(receiving.data(1, b"bc", true), Ok(0));
}

#[test]
fn beyond() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.data(3, b"x", false), Err(Fault::Final));
    assert_eq!(receiving.data(2, b"cd", false), Err(Fault::Final));
    assert_eq!(receiving.data(4, b"", false), Err(Fault::Final));
    assert_eq!(receiving.highest(), 3);
    assert_eq!(receiving.readable(), 3);
    assert_eq!(receiving.data(3, b"", false), Ok(0));
}

#[test]
fn differ() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.data(0, b"ab", true), Err(Fault::Final));
    assert_eq!(receiving.data(0, b"abcd", true), Err(Fault::Final));
    assert_eq!(receiving.size(), Some(3));
}

#[test]
fn below() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abcde", false).unwrap();
    assert_eq!(receiving.data(0, b"ab", true), Err(Fault::Final));
    assert_eq!(receiving.size(), None);
    assert_eq!(receiving.phase(), Phase::Open);
    assert_eq!(receiving.data(5, b"", true), Ok(0));
    assert_eq!(receiving.size(), Some(5));
}

#[test]
fn early() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(5, b"x", true), Ok(6));
    assert_eq!(receiving.phase(), Phase::Sized);
    assert_eq!(receiving.data(0, b"abcde", false), Ok(0));
    assert_eq!(receiving.phase(), Phase::Whole);
}

#[test]
fn flow() {
    let mut receiving = Receiving::new(4);
    assert_eq!(receiving.data(0, b"abcde", true), Err(Fault::Flow));
    assert_eq!(receiving.size(), None);
    assert_eq!(receiving.highest(), 0);
    assert_eq!(receiving.phase(), Phase::Open);
}

#[test]
fn order() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.data(u64::MAX, b"x", false), Err(Fault::Encoding));
    let mut receiving = Receiving::new(1);
    assert_eq!(receiving.data(0, b"abc", true), Err(Fault::Flow));
}

#[test]
fn mismatch() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.reset(1, 4), Err(Fault::Final));
    assert_eq!(receiving.reset(1, 2), Err(Fault::Final));
    assert_eq!(receiving.phase(), Phase::Whole);
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abcde", false).unwrap();
    assert_eq!(receiving.reset(1, 3), Err(Fault::Final));
    assert_eq!(receiving.phase(), Phase::Open);
}

#[test]
fn excess() {
    let mut receiving = Receiving::new(10);
    receiving.data(0, b"abc", false).unwrap();
    assert_eq!(receiving.reset(1, 11), Err(Fault::Flow));
    assert_eq!(receiving.phase(), Phase::Open);
    assert_eq!(receiving.highest(), 3);
    assert_eq!(receiving.reset(1, 10), Ok(7));
}

#[test]
fn counted() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abcd", false).unwrap();
    assert_eq!(receiving.reset(1, 10), Ok(6));
    assert_eq!(receiving.highest(), 10);
    assert_eq!(receiving.phase(), Phase::Reset);
    assert_eq!(receiving.size(), Some(10));
    assert_eq!(receiving.readable(), 0);
}

#[test]
fn ignore() {
    let mut receiving = Receiving::new(100);
    receiving.reset(1, 5).unwrap();
    assert_eq!(receiving.data(0, b"abc", false), Ok(0));
    assert_eq!(receiving.readable(), 0);
    assert!(receiving.read(10).is_empty());
    assert_eq!(receiving.data(0, b"abcdef", false), Err(Fault::Final));
    assert_eq!(receiving.data(0, b"abc", true), Err(Fault::Final));
    assert_eq!(receiving.data(0, b"abcde", true), Ok(0));
    assert_eq!(receiving.highest(), 5);
}

#[test]
fn repeat() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.reset(1, 5), Ok(5));
    assert_eq!(receiving.reset(2, 5), Ok(0));
    assert_eq!(receiving.reset(1, 6), Err(Fault::Final));
    assert_eq!(receiving.reset(1, 4), Err(Fault::Final));
    assert_eq!(receiving.broken(), Some(1));
}

#[test]
fn whole() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.reset(9, 3), Ok(0));
    assert_eq!(receiving.phase(), Phase::Whole);
    assert_eq!(receiving.broken(), None);
    assert_eq!(receiving.read(10), b"abc");
    assert_eq!(receiving.phase(), Phase::Read);
    assert_eq!(receiving.reset(9, 3), Ok(0));
    assert_eq!(receiving.phase(), Phase::Read);
}

#[test]
fn nothing() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.reset(3, 0), Ok(0));
    assert_eq!(receiving.phase(), Phase::Reset);
    assert_eq!(receiving.broken(), Some(3));
}
