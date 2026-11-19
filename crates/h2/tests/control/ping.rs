use crate::support::*;
use h2::{Code, Connection, Error, Fault, Frame, Notice, Settings};

const A: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const B: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

fn ping(ack: bool, data: [u8; 8]) -> Frame {
    Frame::Ping { ack, data }
}

#[test]
fn echo() {
    let mut connection = ready(&[]);
    let reactions = feed(&mut connection, &[ping(false, A)]).unwrap();
    assert_eq!(reactions.len(), 1);
    assert_eq!(reactions[0].reply, vec![ping(true, A)]);
    assert_eq!(reactions[0].notice, None);
}

#[test]
fn answered() {
    let mut connection = ready(&[]);
    connection.send(&ping(false, A)).unwrap();
    let first = connection.receive(&ping(true, A)).unwrap();
    assert_eq!(first.notice, Some(Notice::Pong(A)));
    assert!(first.reply.is_empty());
    let second = connection.receive(&ping(true, A)).unwrap();
    assert_eq!(second.notice, None);
    let stranger = connection.receive(&ping(true, B)).unwrap();
    assert_eq!(stranger.notice, None);
    assert!(stranger.reply.is_empty());
}

#[test]
fn repeated() {
    let mut connection = ready(&[]);
    connection.send(&ping(false, A)).unwrap();
    connection.send(&ping(false, A)).unwrap();
    connection.send(&ping(true, B)).unwrap();
    let ack = ping(true, A);
    assert_eq!(
        connection.receive(&ack).unwrap().notice,
        Some(Notice::Pong(A))
    );
    assert_eq!(
        connection.receive(&ack).unwrap().notice,
        Some(Notice::Pong(A))
    );
    assert_eq!(connection.receive(&ack).unwrap().notice, None);
    assert_eq!(connection.receive(&ping(true, B)).unwrap().notice, None);
}

#[test]
fn early() {
    let fault = Fault::Connection {
        code: Code::Protocol,
    };
    for ack in [false, true] {
        let (mut connection, _) = Connection::start(Settings::default());
        assert_eq!(connection.receive(&ping(ack, A)), Err(fault));
    }
}

#[test]
fn malformed() {
    let connection = ready(&[]);
    let codec = connection.inbound();
    let mut onstream = vec![0, 0, 8, 6, 0, 0, 0, 0, 1];
    onstream.extend(A);
    assert_eq!(codec.decode(&onstream), Err(Error::Stream));
    let mut short = vec![0, 0, 7, 6, 0, 0, 0, 0, 0];
    short.extend(&A[..7]);
    assert_eq!(codec.decode(&short), Err(Error::Length));
    let mut long = vec![0, 0, 9, 6, 0, 0, 0, 0, 0];
    long.extend(A);
    long.push(9);
    assert_eq!(codec.decode(&long), Err(Error::Length));
}
