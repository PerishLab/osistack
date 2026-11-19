use crate::support::*;

#[test]
fn split() {
    let mut streams = opened(5);
    assert_eq!(streams.goaway(8), Ok(vec![8, 12, 16]));
    assert_eq!(streams.active(), vec![0, 4]);
    assert_eq!(streams.going(), Some(8));
}

#[test]
fn everything() {
    let mut streams = opened(5);
    assert_eq!(streams.goaway(0), Ok(vec![0, 4, 8, 12, 16]));
    assert!(streams.active().is_empty());
    assert_eq!(streams.going(), Some(0));
}

#[test]
fn lowered() {
    let mut streams = opened(5);
    assert_eq!(streams.goaway(12), Ok(vec![12, 16]));
    assert_eq!(streams.goaway(4), Ok(vec![4, 8]));
    assert_eq!(streams.active(), vec![0]);
    assert_eq!(streams.goaway(0), Ok(vec![0]));
    assert!(streams.active().is_empty());
}

#[test]
fn repeated() {
    let mut streams = opened(4);
    assert_eq!(streams.goaway(8), Ok(vec![8, 12]));
    assert_eq!(streams.goaway(8), Ok(vec![]));
    assert_eq!(streams.active(), vec![0, 4]);
    assert_eq!(streams.going(), Some(8));
}

#[test]
fn finished() {
    let mut streams = opened(5);
    assert!(streams.close(12));
    assert!(streams.close(0));
    assert_eq!(streams.goaway(8), Ok(vec![8, 16]));
    assert_eq!(streams.active(), vec![4]);
}

#[test]
fn beyond() {
    let mut streams = opened(2);
    assert_eq!(streams.goaway(400), Ok(vec![]));
    assert_eq!(streams.active(), vec![0, 4]);
    assert_eq!(streams.going(), Some(400));
    assert_eq!(streams.goaway(4), Ok(vec![4]));
}
