use quic::Credit;

#[test]
fn taken() {
    let mut credit = Credit::new(10);
    assert_eq!((credit.limit(), credit.used(), credit.room()), (10, 0, 10));
    assert_eq!(credit.take(4), 4);
    assert_eq!((credit.used(), credit.room()), (4, 6));
    assert_eq!(credit.take(100), 6);
    assert_eq!((credit.used(), credit.room()), (10, 0));
    assert_eq!(credit.take(1), 0);
    assert_eq!(credit.take(0), 0);
    assert_eq!(credit.used(), 10);
}

#[test]
fn both() {
    let mut stream = Credit::new(10);
    let mut total = Credit::new(6);
    assert_eq!(stream.share(&mut total, 100), 6);
    assert_eq!((stream.used(), total.used()), (6, 6));
    assert_eq!(stream.share(&mut total, 1), 0);
    assert!(total.raise(20));
    assert_eq!(stream.share(&mut total, 100), 4);
    assert_eq!((stream.used(), total.used()), (10, 10));
    assert_eq!(stream.share(&mut total, 1), 0);
    assert_eq!(total.room(), 10);
}

#[test]
fn wide() {
    let mut stream = Credit::new(100);
    let mut total = Credit::new(100);
    assert_eq!(stream.share(&mut total, 30), 30);
    assert_eq!(stream.share(&mut total, 0), 0);
    assert_eq!((stream.used(), total.used()), (30, 30));
    assert_eq!(total.take(50), 50);
    assert_eq!(stream.share(&mut total, 100), 20);
    assert_eq!((stream.used(), total.used()), (50, 100));
}

#[test]
fn raised() {
    let mut credit = Credit::new(10);
    credit.take(7);
    assert!(!credit.raise(5));
    assert!(!credit.raise(10));
    assert_eq!(credit.limit(), 10);
    assert!(credit.raise(11));
    assert_eq!((credit.limit(), credit.used(), credit.room()), (11, 7, 4));
    assert!(!credit.raise(0));
    assert_eq!(credit.limit(), 11);
}

#[test]
fn stalled() {
    let mut credit = Credit::new(2);
    assert_eq!(credit.stalled(), None);
    credit.take(2);
    assert_eq!(credit.stalled(), Some(2));
    assert_eq!(credit.stalled(), None);
    assert!(!credit.raise(2));
    assert_eq!(credit.stalled(), None);
    assert!(credit.raise(5));
    assert_eq!(credit.stalled(), None);
    credit.take(3);
    assert_eq!(credit.stalled(), Some(5));
    assert_eq!(credit.stalled(), None);
}

#[test]
fn zero() {
    let mut credit = Credit::new(0);
    assert_eq!(credit.stalled(), Some(0));
    assert_eq!(credit.stalled(), None);
    assert_eq!(credit.take(1), 0);
    assert!(credit.raise(1));
    assert_eq!(credit.stalled(), None);
    assert_eq!(credit.take(5), 1);
    assert_eq!(credit.stalled(), Some(1));
}
