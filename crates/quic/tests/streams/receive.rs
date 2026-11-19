use quic::{Fault, Phase, Receiving};

#[test]
fn fresh() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.phase(), Phase::Open);
    assert_eq!(receiving.highest(), 0);
    assert_eq!(receiving.readable(), 0);
    assert_eq!(receiving.size(), None);
    assert_eq!(receiving.limit(), 100);
    assert!(receiving.read(10).is_empty());
    assert_eq!(receiving.grant(), None);
}

#[test]
fn order() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(0, b"abcd", false), Ok(4));
    assert_eq!(receiving.readable(), 4);
    assert_eq!(receiving.read(2), b"ab");
    assert_eq!(receiving.readable(), 2);
    assert_eq!(receiving.read(10), b"cd");
    assert!(receiving.read(10).is_empty());
    assert_eq!(receiving.highest(), 4);
}

#[test]
fn hole() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(4, b"efgh", false), Ok(8));
    assert_eq!(receiving.readable(), 0);
    assert!(receiving.read(10).is_empty());
    assert_eq!(receiving.data(0, b"abcd", false), Ok(0));
    assert_eq!(receiving.readable(), 8);
    assert_eq!(receiving.read(8), b"abcdefgh");
}

#[test]
fn zero() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(0, b"", false), Ok(0));
    assert_eq!(receiving.highest(), 0);
    assert_eq!(receiving.data(5, b"", false), Ok(5));
    assert_eq!(receiving.highest(), 5);
    assert_eq!(receiving.readable(), 0);
    assert!(receiving.read(0).is_empty());
}

#[test]
fn split() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abcdef", false).unwrap();
    assert!(receiving.read(0).is_empty());
    assert_eq!(receiving.readable(), 6);
    assert_eq!(receiving.read(4), b"abcd");
    assert_eq!(receiving.read(4), b"ef");
}

#[test]
fn twice() {
    let mut receiving = Receiving::new(100);
    assert_eq!(receiving.data(0, b"abc", false), Ok(3));
    assert_eq!(receiving.data(0, b"abc", false), Ok(0));
    assert_eq!(receiving.readable(), 3);
    assert_eq!(receiving.read(10), b"abc");
}

#[test]
fn spent() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, b"abc", false).unwrap();
    assert_eq!(receiving.read(3), b"abc");
    assert_eq!(receiving.data(0, b"abc", false), Ok(0));
    assert_eq!(receiving.readable(), 0);
    assert!(receiving.read(10).is_empty());
}

#[test]
fn limit() {
    let mut receiving = Receiving::new(10);
    assert_eq!(receiving.data(0, &[1; 11], false), Err(Fault::Flow));
    assert_eq!(receiving.highest(), 0);
    assert_eq!(receiving.readable(), 0);
    assert_eq!(receiving.data(0, &[1; 10], false), Ok(10));
    assert_eq!(receiving.data(5, &[1; 6], false), Err(Fault::Flow));
    assert_eq!(receiving.highest(), 10);
    assert_eq!(receiving.data(10, b"", false), Ok(0));
    assert_eq!(receiving.data(11, b"", false), Err(Fault::Flow));
}

#[test]
fn grant() {
    let mut receiving = Receiving::new(100);
    receiving.data(0, &[7; 60], false).unwrap();
    assert_eq!(receiving.grant(), None);
    assert_eq!(receiving.read(49).len(), 49);
    assert_eq!(receiving.grant(), None);
    assert_eq!(receiving.read(1).len(), 1);
    assert_eq!(receiving.grant(), Some(150));
    assert_eq!(receiving.limit(), 150);
    assert_eq!(receiving.grant(), None);
    assert_eq!(receiving.data(60, &[7; 90], false), Ok(90));
    assert_eq!(receiving.data(150, b"x", false), Err(Fault::Flow));
}

#[test]
fn encoding() {
    let mut receiving = Receiving::new(u64::MAX);
    assert_eq!(
        receiving.data(u64::MAX - 1, b"abc", false),
        Err(Fault::Encoding)
    );
    assert_eq!(receiving.data(1 << 62, b"", false), Err(Fault::Encoding));
    assert_eq!(
        receiving.data((1 << 62) - 1, b"a", false),
        Err(Fault::Encoding)
    );
    assert_eq!(receiving.highest(), 0);
    assert_eq!(
        receiving.data((1 << 62) - 2, b"a", false),
        Ok((1 << 62) - 1)
    );
    assert_eq!(receiving.highest(), (1 << 62) - 1);
    assert_eq!(receiving.data((1 << 62) - 1, b"", false), Ok(0));
}
