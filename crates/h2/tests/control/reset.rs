use crate::support::*;
use h2::{Close, Code, Fault, Frame, Misuse, Notice, Outcome, State};

const PROTOCOL: Fault = Fault::Connection {
    code: Code::Protocol,
};

#[test]
fn received() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false), (3, false)]);
    let reaction = connection.receive(&Stream(1).reset(8)).unwrap();
    assert_eq!(reaction.outcome, Outcome::Accept);
    assert_eq!(reaction.notice, Some(Notice::Reset { stream: 1, code: 8 }));
    assert_eq!(
        connection.streams().state(1),
        State::Closed(Close::Received)
    );
    assert!(connection.flow().outgoing(1).is_none());
    assert!(connection.flow().incoming(1).is_none());
    assert_eq!(connection.send(&Stream(1).data(1)), Err(Misuse::Closed));
    assert_eq!(connection.streams().state(3), State::Open);
}

#[test]
fn dropped() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false)]);
    connection.send(&Stream(1).reset(0)).unwrap();
    let reaction = connection.receive(&Stream(1).reset(8)).unwrap();
    assert_eq!(reaction.outcome, Outcome::Discard);
    assert_eq!(reaction.notice, None);
}

#[test]
fn invalid() {
    let mut connection = ready(&[]);
    assert_eq!(connection.receive(&Stream(5).reset(8)), Err(PROTOCOL));
    let zero = Frame::Reset { stream: 0, code: 8 };
    assert_eq!(connection.receive(&zero), Err(PROTOCOL));
}

#[test]
fn twice() {
    let mut connection = ready(&[]);
    opened(&mut connection, &[(1, false)]);
    connection.receive(&Stream(1).reset(8)).unwrap();
    let again = connection.receive(&Stream(1).reset(9)).unwrap();
    assert_eq!(again.outcome, Outcome::Discard);
    assert_eq!(again.notice, None);
}
