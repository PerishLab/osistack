use quic::{Fault, Inbound};

#[test]
fn fin() {
    let mut stream = Inbound::new(100);
    assert_eq!(stream.last(), None);
    assert_eq!(stream.data(0, 10, false), Ok(10));
    assert_eq!(stream.last(), None);
    assert_eq!(stream.data(10, 10, true), Ok(10));
    assert_eq!(stream.last(), Some(20));
}

#[test]
fn beyond() {
    let mut stream = Inbound::new(100);
    stream.data(0, 20, true).unwrap();
    assert_eq!(stream.data(20, 1, false), Err(Fault::Final));
    assert_eq!(stream.data(15, 10, false), Err(Fault::Final));
    assert_eq!(stream.data(25, 0, false), Err(Fault::Final));
    assert_eq!(stream.data(10, 10, false), Ok(0));
    assert_eq!(stream.data(20, 0, false), Ok(0));
    assert_eq!(stream.last(), Some(20));
}

#[test]
fn moved() {
    let mut stream = Inbound::new(100);
    stream.data(0, 20, true).unwrap();
    assert_eq!(stream.data(0, 19, true), Err(Fault::Final));
    assert_eq!(stream.data(0, 21, true), Err(Fault::Final));
    assert_eq!(stream.data(0, 20, true), Ok(0));
    assert_eq!(stream.last(), Some(20));
}

#[test]
fn smaller() {
    let mut stream = Inbound::new(100);
    stream.data(0, 30, false).unwrap();
    assert_eq!(stream.data(0, 20, true), Err(Fault::Final));
    assert_eq!(stream.last(), None);
    assert_eq!(stream.allowance().highest(), 30);
    assert_eq!(stream.data(0, 30, true), Ok(0));
    assert_eq!(stream.last(), Some(30));
}

#[test]
fn reset() {
    let mut stream = Inbound::new(1000);
    stream.data(0, 100, false).unwrap();
    assert_eq!(stream.reset(300), Ok(200));
    assert_eq!(stream.last(), Some(300));
    assert_eq!(stream.reset(300), Ok(0));
    assert_eq!(stream.reset(301), Err(Fault::Final));
    assert_eq!(stream.reset(299), Err(Fault::Final));
    assert_eq!(stream.last(), Some(300));
    assert_eq!(stream.data(300, 1, false), Err(Fault::Final));
}

#[test]
fn trimmed() {
    let mut stream = Inbound::new(1000);
    stream.data(0, 100, false).unwrap();
    assert_eq!(stream.reset(50), Err(Fault::Final));
    assert_eq!(stream.last(), None);
    assert_eq!(stream.reset(100), Ok(0));
    let mut other = Inbound::new(1000);
    other.data(0, 100, true).unwrap();
    assert_eq!(other.reset(100), Ok(0));
    assert_eq!(other.reset(120), Err(Fault::Final));
}

#[test]
fn over() {
    let mut stream = Inbound::new(100);
    assert_eq!(stream.data(0, 101, true), Err(Fault::Flow));
    assert_eq!(stream.last(), None);
    assert_eq!(stream.allowance().highest(), 0);
    assert_eq!(stream.reset(101), Err(Fault::Flow));
    assert_eq!(stream.last(), None);
    assert_eq!(stream.data(90, 10, true), Ok(100));
    assert_eq!(stream.last(), Some(100));
}

#[test]
fn granted() {
    let mut stream = Inbound::new(100);
    stream.data(0, 100, false).unwrap();
    stream.consume(49);
    assert_eq!(stream.grant(), None);
    stream.consume(1);
    assert_eq!(stream.grant(), Some(150));
    assert_eq!(stream.allowance().limit(), 150);
    assert_eq!(stream.allowance().consumed(), 50);
}

#[test]
fn alike() {
    for size in [0, 1, 50, 99, 100, 101, 400] {
        let mut left = Inbound::new(200);
        let mut right = Inbound::new(200);
        left.data(0, 100, false).unwrap();
        right.data(0, 100, false).unwrap();
        assert_eq!(left.reset(size), right.data(size, 0, true), "{size}");
        assert_eq!(left.last(), right.last(), "{size}");
        assert_eq!(left.allowance(), right.allowance(), "{size}");
    }
}
