use crate::support::*;
use h2::{Close, Misuse, State, Streams};

#[test]
fn rising() {
    let mut streams = Streams::new();
    assert_eq!(streams.next(), Ok(1));
    streams.send(&Stream(1).headers(true)).unwrap();
    assert_eq!(streams.next(), Ok(3));
    streams.send(&Stream(3).headers(false)).unwrap();
    assert_eq!(streams.next(), Ok(5));
}

#[test]
fn skipped() {
    let mut streams = Streams::new();
    streams.send(&Stream(7).headers(false)).unwrap();
    for id in [1, 3, 5] {
        assert_eq!(streams.state(id), State::Closed(Close::Finished));
        assert_eq!(
            streams.send(&Stream(id).headers(false)),
            Err(Misuse::Closed)
        );
    }
    assert_eq!(streams.state(9), State::Idle);
    assert_eq!(streams.next(), Ok(9));
}

#[test]
fn reuse() {
    let mut streams = Streams::new();
    streams.send(&Stream(1).headers(false)).unwrap();
    streams.send(&Stream(1).reset()).unwrap();
    assert_eq!(streams.send(&Stream(1).headers(false)), Err(Misuse::Closed));
}

#[test]
fn even() {
    let mut streams = Streams::new();
    assert_eq!(streams.state(2), State::Idle);
    assert_eq!(streams.send(&Stream(2).headers(false)), Err(Misuse::Parity));
    assert_eq!(streams.send(&Stream(2).data(false)), Err(Misuse::Parity));
    assert_eq!(streams.send(&Stream(2).priority()), Ok(()));
    assert_eq!(streams.state(2), State::Idle);
}

#[test]
fn zero() {
    let mut streams = Streams::new();
    assert_eq!(streams.send(&Stream(0).headers(false)), Err(Misuse::Zero));
    assert_eq!(streams.send(&Stream(0).data(false)), Err(Misuse::Zero));
    assert_eq!(streams.send(&Stream(0).reset()), Err(Misuse::Zero));
}

#[test]
fn exhausted() {
    let mut streams = Streams::new();
    streams.send(&Stream(0x7fff_fffd).headers(false)).unwrap();
    assert_eq!(streams.next(), Ok(0x7fff_ffff));
    streams.send(&Stream(0x7fff_ffff).headers(false)).unwrap();
    assert_eq!(streams.next(), Err(Misuse::Exhausted));
    assert_eq!(streams.state(0x7fff_ffff), State::Open);
}
