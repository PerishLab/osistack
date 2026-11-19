use quic::{Fault, Phase, Receiving};

#[test]
fn walk() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.phase(), Phase::Open);
    receiving.data(3, b"d", true).unwrap();
    assert_eq!(receiving.phase(), Phase::Sized);
    receiving.data(0, b"abc", false).unwrap();
    assert_eq!(receiving.phase(), Phase::Whole);
    assert_eq!(receiving.read(2), b"ab");
    assert_eq!(receiving.phase(), Phase::Whole);
    assert_eq!(receiving.read(1), b"c");
    assert_eq!(receiving.phase(), Phase::Whole);
    assert_eq!(receiving.read(1), b"d");
    assert_eq!(receiving.phase(), Phase::Read);
}

#[test]
fn first() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.phase(), Phase::Whole);
    assert_eq!(receiving.read(10), b"abc");
    assert_eq!(receiving.phase(), Phase::Read);
}

#[test]
fn empty() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(0, b"", true), Ok(0));
    assert_eq!(receiving.size(), Some(0));
    assert_eq!(receiving.phase(), Phase::Read);
}

#[test]
fn broken() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.broken(), None);
    receiving.data(0, b"abc", false).unwrap();
    assert_eq!(receiving.broken(), None);
    receiving.reset(7, 5).unwrap();
    assert_eq!(receiving.phase(), Phase::Reset);
    assert_eq!(receiving.broken(), Some(7));
    assert_eq!(receiving.phase(), Phase::Gone);
    assert_eq!(receiving.broken(), None);
    assert_eq!(receiving.reset(8, 5), Ok(0));
    assert_eq!(receiving.phase(), Phase::Gone);
    assert!(receiving.read(10).is_empty());
}

#[test]
fn stop() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.stop(3), Some(3));
    assert_eq!(receiving.stop(4), None);
    assert_eq!(receiving.data(0, b"abcd", false), Ok(4));
    assert_eq!(receiving.readable(), 0);
    assert!(receiving.read(10).is_empty());
    assert_eq!(receiving.highest(), 4);
    assert_eq!(receiving.phase(), Phase::Open);
    assert_eq!(receiving.data(4, b"", true), Ok(0));
    assert_eq!(receiving.phase(), Phase::Read);
}

#[test]
fn sized() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"ab", false).unwrap();
    receiving.data(4, b"ef", true).unwrap();
    assert_eq!(receiving.phase(), Phase::Sized);
    assert_eq!(receiving.stop(1), Some(1));
    assert_eq!(receiving.phase(), Phase::Sized);
    assert_eq!(receiving.data(2, b"cd", false), Ok(0));
    assert_eq!(receiving.phase(), Phase::Read);
}

#[test]
fn discard() {
    let mut receiving = Receiving::new(10);
    receiving.data(0, b"abcdefgh", false).unwrap();
    assert_eq!(receiving.grant(), None);
    assert_eq!(receiving.stop(1), Some(1));
    assert_eq!(receiving.readable(), 0);
    assert_eq!(receiving.highest(), 8);
    assert_eq!(receiving.grant(), Some(18));
}

#[test]
fn counted() {
    let mut receiving = Receiving::new(10);
    receiving.stop(1);
    receiving.data(0, b"abcdefgh", false).unwrap();
    assert_eq!(receiving.grant(), Some(18));
    assert_eq!(receiving.data(8, &[0; 10], false), Ok(10));
    assert_eq!(receiving.data(18, b"x", false), Err(Fault::Flow));
}

#[test]
fn refused() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", true).unwrap();
    assert_eq!(receiving.stop(1), None);
    receiving.read(10);
    assert_eq!(receiving.phase(), Phase::Read);
    assert_eq!(receiving.stop(1), None);
    let mut receiving = Receiving::new(100);
    receiving.reset(1, 3).unwrap();
    assert_eq!(receiving.stop(1), None);
    receiving.broken();
    assert_eq!(receiving.stop(1), None);
}

#[test]
fn after() {
    let mut receiving = Receiving::new(100);
    receiving.stop(2);
    assert_eq!(receiving.reset(5, 4), Ok(4));
    assert_eq!(receiving.phase(), Phase::Reset);
    assert_eq!(receiving.broken(), Some(5));
    assert_eq!(receiving.phase(), Phase::Gone);
}
