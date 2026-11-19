use crate::support::*;
use h3::{Going, Streams};

#[test]
fn numbered() {
    let mut streams = Streams::new();
    assert_eq!(streams.going(), None);
    assert!(streams.active().is_empty());
    let ids: Vec<u64> = (0..5).map(|_| streams.open().unwrap()).collect();
    assert_eq!(ids, vec![0, 4, 8, 12, 16]);
    assert_eq!(streams.active(), ids);
}

#[test]
fn closed() {
    let mut streams = opened(4);
    assert!(streams.close(4));
    assert!(!streams.close(4));
    assert!(!streams.close(6));
    assert!(!streams.close(40));
    assert_eq!(streams.active(), vec![0, 8, 12]);
    assert_eq!(streams.open(), Ok(16));
    assert_eq!(streams.active(), vec![0, 8, 12, 16]);
}

#[test]
fn refused() {
    let mut streams = opened(3);
    assert_eq!(streams.goaway(8), Ok(vec![8]));
    assert_eq!(streams.open(), Err(Going(8)));
    assert_eq!(streams.open(), Err(Going(8)));
    assert_eq!(streams.active(), vec![0, 4]);
    assert_eq!(streams.goaway(4), Ok(vec![4]));
    assert_eq!(streams.open(), Err(Going(4)));
    assert_eq!(streams.going(), Some(4));
    assert_eq!(streams.active(), vec![0]);
}

#[test]
fn kept() {
    let mut streams = opened(2);
    assert_eq!(streams.goaway(8), Ok(vec![]));
    assert_eq!(streams.open(), Err(Going(8)));
    let mut next = Streams::new();
    next.goaway(0).unwrap();
    assert_eq!(next.open(), Err(Going(0)));
    assert!(next.active().is_empty());
}
