use crate::support::*;
use h2::{Close, Outcome, State, Streams};

fn open() -> Streams {
    let mut streams = Streams::new();
    streams.send(&Stream(1).headers(false)).unwrap();
    streams
}

#[test]
fn exchange() {
    let mut streams = Streams::new();
    assert_eq!(streams.state(1), State::Idle);
    streams.send(&Stream(1).headers(false)).unwrap();
    assert_eq!(streams.state(1), State::Open);
    streams.send(&Stream(1).data(true)).unwrap();
    assert_eq!(streams.state(1), State::Local);
    assert_eq!(
        streams.receive(&Stream(1).headers(false)),
        Ok(Outcome::Accept)
    );
    assert_eq!(streams.receive(&Stream(1).data(false)), Ok(Outcome::Accept));
    assert_eq!(streams.state(1), State::Local);
    assert_eq!(streams.receive(&Stream(1).data(true)), Ok(Outcome::Accept));
    assert_eq!(streams.state(1), State::Closed(Close::Finished));
    assert_eq!(streams.active(), 0);
}

#[test]
fn bodiless() {
    let mut streams = Streams::new();
    streams.send(&Stream(1).headers(true)).unwrap();
    assert_eq!(streams.state(1), State::Local);
    assert_eq!(streams.active(), 1);
}

#[test]
fn early() {
    let mut streams = open();
    streams.receive(&Stream(1).headers(true)).unwrap();
    assert_eq!(streams.state(1), State::Remote);
    streams.send(&Stream(1).data(false)).unwrap();
    assert_eq!(streams.state(1), State::Remote);
    streams.send(&Stream(1).data(true)).unwrap();
    assert_eq!(streams.state(1), State::Closed(Close::Finished));
}

#[test]
fn aborted() {
    let mut streams = open();
    streams.send(&Stream(1).reset()).unwrap();
    assert_eq!(streams.state(1), State::Closed(Close::Sent));
    assert_eq!(streams.active(), 0);
}

#[test]
fn refused() {
    let mut streams = open();
    streams.receive(&Stream(1).reset()).unwrap();
    assert_eq!(streams.state(1), State::Closed(Close::Received));
}

#[test]
fn everywhere() {
    for fins in [(false, false), (true, false), (false, true)] {
        let mut streams = Streams::new();
        streams.send(&Stream(1).headers(fins.0)).unwrap();
        if fins.1 {
            streams.receive(&Stream(1).headers(true)).unwrap();
        }
        streams.send(&Stream(1).reset()).unwrap();
        assert_eq!(streams.state(1), State::Closed(Close::Sent));
    }
}

#[test]
fn control() {
    let mut streams = open();
    for frame in [Stream(1).window(), Stream(1).priority(), Stream(1).more()] {
        assert_eq!(streams.receive(&frame), Ok(Outcome::Accept));
        assert_eq!(streams.state(1), State::Open);
    }
    streams.send(&Stream(1).window()).unwrap();
    streams.send(&Stream(1).priority()).unwrap();
    assert_eq!(streams.state(1), State::Open);
}

#[test]
fn updates() {
    let mut streams = open();
    streams.send(&Stream(1).data(true)).unwrap();
    streams.send(&Stream(1).window()).unwrap();
    streams.send(&Stream(1).priority()).unwrap();
    assert_eq!(streams.state(1), State::Local);
}

#[test]
fn connection() {
    let mut streams = Streams::new();
    assert_eq!(streams.send(&Stream(0).window()), Ok(()));
    assert_eq!(streams.receive(&Stream(0).window()), Ok(Outcome::Accept));
    assert_eq!(streams.active(), 0);
}

#[test]
fn counting() {
    let mut streams = Streams::new();
    for id in [1, 3, 5] {
        streams.send(&Stream(id).headers(false)).unwrap();
    }
    assert_eq!(streams.active(), 3);
    streams.send(&Stream(3).reset()).unwrap();
    assert_eq!(streams.active(), 2);
}
