use crate::support::*;
use h2::{Close, Code, Fault, Misuse, Outcome, State, Streams};

const PROTOCOL: Fault = Fault::Connection {
    code: Code::Protocol,
};
const CLOSED: Fault = Fault::Connection { code: Code::Closed };

fn stream(id: u32) -> Fault {
    Fault::Stream {
        stream: id,
        code: Code::Closed,
    }
}

fn remote() -> Streams {
    let mut streams = Streams::new();
    streams.send(&Stream(1).headers(false)).unwrap();
    streams.receive(&Stream(1).headers(true)).unwrap();
    streams
}

fn dead(reason: Close) -> Streams {
    let mut streams = Streams::new();
    streams.send(&Stream(1).headers(false)).unwrap();
    match reason {
        Close::Sent => streams.send(&Stream(1).reset()).unwrap(),
        Close::Received => {
            streams.receive(&Stream(1).reset()).unwrap();
        }
        Close::Finished => {
            streams.send(&Stream(1).data(true)).unwrap();
            streams.receive(&Stream(1).headers(true)).unwrap();
        }
    }
    streams
}

#[test]
fn codes() {
    assert_eq!(Code::Protocol.get(), 1);
    assert_eq!(Code::Closed.get(), 5);
}

#[test]
fn receiving() {
    let mut streams = Streams::new();
    for frame in [
        Stream(1).headers(false),
        Stream(1).data(false),
        Stream(1).reset(),
        Stream(1).window(),
        Stream(1).more(),
    ] {
        assert_eq!(streams.receive(&frame), Err(PROTOCOL));
    }
    assert_eq!(streams.receive(&Stream(1).priority()), Ok(Outcome::Accept));
    assert_eq!(streams.receive(&Stream(2).headers(false)), Err(PROTOCOL));
    assert_eq!(streams.state(1), State::Idle);
}

#[test]
fn sending() {
    let mut streams = Streams::new();
    for frame in [
        Stream(1).data(false),
        Stream(1).reset(),
        Stream(1).window(),
        Stream(1).more(),
    ] {
        assert_eq!(streams.send(&frame), Err(Misuse::Idle));
    }
    assert_eq!(streams.state(1), State::Idle);
}

#[test]
fn inbound() {
    for frame in [
        Stream(1).data(false),
        Stream(1).data(true),
        Stream(1).headers(false),
        Stream(1).more(),
    ] {
        let mut streams = remote();
        assert_eq!(streams.receive(&frame), Err(stream(1)));
    }
    let mut streams = remote();
    assert_eq!(streams.receive(&Stream(1).window()), Ok(Outcome::Accept));
    assert_eq!(streams.receive(&Stream(1).priority()), Ok(Outcome::Accept));
    assert_eq!(streams.receive(&Stream(1).reset()), Ok(Outcome::Accept));
    assert_eq!(streams.state(1), State::Closed(Close::Received));
}

#[test]
fn local() {
    let mut streams = Streams::new();
    streams.send(&Stream(1).headers(true)).unwrap();
    for frame in [
        Stream(1).data(false),
        Stream(1).headers(false),
        Stream(1).more(),
    ] {
        assert_eq!(streams.send(&frame), Err(Misuse::Half));
    }
    assert_eq!(streams.state(1), State::Local);
}

#[test]
fn sealed() {
    for reason in [Close::Finished, Close::Sent, Close::Received] {
        let mut streams = dead(reason);
        for frame in [
            Stream(1).data(false),
            Stream(1).reset(),
            Stream(1).window(),
            Stream(1).more(),
        ] {
            assert_eq!(streams.send(&frame), Err(Misuse::Closed));
        }
        assert_eq!(streams.send(&Stream(1).priority()), Ok(()));
    }
}

#[test]
fn discard() {
    let mut streams = dead(Close::Sent);
    for frame in [
        Stream(1).data(false),
        Stream(1).headers(true),
        Stream(1).more(),
        Stream(1).window(),
        Stream(1).reset(),
    ] {
        assert_eq!(streams.receive(&frame), Ok(Outcome::Discard));
    }
    assert_eq!(streams.state(1), State::Closed(Close::Sent));
}

#[test]
fn tolerate() {
    for reason in [Close::Finished, Close::Received] {
        let mut streams = dead(reason);
        assert_eq!(streams.receive(&Stream(1).window()), Ok(Outcome::Discard));
        assert_eq!(streams.receive(&Stream(1).reset()), Ok(Outcome::Discard));
        assert_eq!(streams.receive(&Stream(1).priority()), Ok(Outcome::Accept));
        for frame in [
            Stream(1).data(false),
            Stream(1).headers(false),
            Stream(1).more(),
        ] {
            assert_eq!(streams.receive(&frame), Err(CLOSED));
        }
    }
}

#[test]
fn ghost() {
    let mut streams = Streams::new();
    streams.send(&Stream(5).headers(false)).unwrap();
    assert_eq!(streams.receive(&Stream(3).data(false)), Err(CLOSED));
    assert_eq!(streams.receive(&Stream(3).window()), Ok(Outcome::Discard));
}

#[test]
fn atomic() {
    let mut streams = remote();
    streams.receive(&Stream(1).data(false)).unwrap_err();
    assert_eq!(streams.state(1), State::Remote);
    assert_eq!(streams.active(), 1);
}
