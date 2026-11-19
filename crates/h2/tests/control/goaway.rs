use crate::support::*;
use h2::{Close, Code, Fault, Frame, Misuse, Notice, Outcome, State};

fn goaway(last: u32, code: u32) -> Frame {
    Frame::Goaway {
        last,
        code,
        debug: b"bye".to_vec(),
    }
}

const PROTOCOL: Fault = Fault::Connection {
    code: Code::Protocol,
};

fn notice(last: u32, code: u32, unprocessed: &[u32]) -> Notice {
    Notice::Goaway {
        last,
        code,
        debug: b"bye".to_vec(),
        unprocessed: unprocessed.to_vec(),
    }
}

#[test]
fn received() {
    let mut connection = ready(&[]);
    opened(
        &mut connection,
        &[(1, false), (3, false), (5, false), (7, false)],
    );
    opened(&mut connection, &[(9, true)]);
    connection.send(&Stream(7).reset(8)).unwrap();
    let reaction = connection.receive(&goaway(3, 2)).unwrap();
    assert_eq!(reaction.notice, Some(notice(3, 2, &[5, 9])));
    assert_eq!(reaction.outcome, Outcome::Accept);
    let states = connection.streams();
    assert_eq!(states.state(1), State::Open);
    assert_eq!(states.state(3), State::Open);
    for stream in [5, 9] {
        assert_eq!(states.state(stream), State::Closed(Close::Sent));
        assert!(connection.flow().outgoing(stream).is_none());
        assert!(connection.flow().incoming(stream).is_none());
    }
    assert!(connection.flow().outgoing(1).is_some());
    connection.send(&Stream(1).data(10)).unwrap();
    connection.receive(&Stream(3).data(10)).unwrap();
}

#[test]
fn dropped() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false), (3, false)]);
    connection.receive(&goaway(1, 0)).unwrap();
    let literal = [&[0x40, 5][..], b"x-key", &[5], b"value"].concat();
    let late = connection.receive(&Stream(3).block(&literal)).unwrap();
    assert_eq!(late.outcome, Outcome::Discard);
    assert!(late.block.is_none());
    assert_eq!(connection.decoder().size(), 42);
    let data = connection.receive(&Stream(3).data(5)).unwrap();
    assert_eq!(data.outcome, Outcome::Discard);
    let kept = connection.receive(&Stream(1).headers(false)).unwrap();
    assert!(kept.block.is_some());
}

#[test]
fn fresh() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false)]);
    connection.receive(&goaway(1, 0)).unwrap();
    let list = [pair(":method", "GET")];
    assert_eq!(connection.headers(3, &list, false), Err(Misuse::Going));
    assert_eq!(
        connection.send(&Stream(3).headers(false)),
        Err(Misuse::Going)
    );
    connection.headers(1, &list, true).unwrap();
    assert_eq!(connection.send(&Stream(1).data(1)), Err(Misuse::Half));
}

#[test]
fn raised() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false), (3, false), (5, false)]);
    let first = connection.receive(&goaway(3, 0)).unwrap();
    assert_eq!(first.notice, Some(notice(3, 0, &[5])));
    assert_eq!(connection.receive(&goaway(5, 0)), Err(PROTOCOL));
    let same = connection.receive(&goaway(3, 1)).unwrap();
    assert_eq!(same.notice, Some(notice(3, 1, &[])));
    let lower = connection.receive(&goaway(1, 1)).unwrap();
    assert_eq!(lower.notice, Some(notice(1, 1, &[3])));
}

#[test]
fn everything() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false), (3, true)]);
    let reaction = connection.receive(&goaway(0, 0)).unwrap();
    assert_eq!(reaction.notice, Some(notice(0, 0, &[1, 3])));
    assert_eq!(connection.streams().active(), 0);
}

#[test]
fn early() {
    let (mut connection, _) = h2::Connection::start(h2::Settings::default());
    assert_eq!(connection.receive(&goaway(0, 0)), Err(PROTOCOL));
}

#[test]
fn sent() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false)]);
    assert_eq!(connection.send(&goaway(1, 0)), Err(Misuse::Last));
    connection.send(&goaway(0, 0)).unwrap();
    connection.send(&goaway(0, 2)).unwrap();
    connection.send(&Stream(1).data(1)).unwrap();
    assert!(connection.send(&Stream(3).headers(false)).is_ok());
}
