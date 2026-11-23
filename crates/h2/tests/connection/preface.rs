use crate::support::*;
use h2::{Codec, Connection, Frame, Misuse, Outcome, PREFACE, Settings, State};

const EMPTY: [u8; 9] = [0, 0, 0, 4, 0, 0, 0, 0, 0];
const ACK: [u8; 9] = [0, 0, 0, 4, 1, 0, 0, 0, 0];

#[test]
fn bytes() {
    let (connection, bytes) = Connection::start(Settings::default()).unwrap();
    assert_eq!(&bytes[..24], &PREFACE[..]);
    assert_eq!(
        &bytes[24..],
        &[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0][..]
    );
    assert_eq!(connection.unacknowledged(), 1);
    assert!(!connection.ready());
    assert_eq!(connection.local(), &Settings::default());
}

#[test]
fn custom() {
    let wanted = Settings {
        window: 1_048_576,
        frame: 32_768,
        ..Settings::default()
    };
    let (_, bytes) = Connection::start(wanted).unwrap();
    let expect = [
        0, 0, 18, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 5, 0, 0, 128, 0,
    ];
    assert_eq!(&bytes[24..], &expect[..]);
}

#[test]
fn acknowledge() {
    let (mut connection, _) = Connection::start(Settings::default()).unwrap();
    let codec = Codec::default();
    let (frame, used) = codec.decode(&EMPTY).unwrap().unwrap();
    assert_eq!(used, 9);
    let reaction = connection.receive(&frame).unwrap();
    assert_eq!(reaction.outcome, Outcome::Accept);
    assert_eq!(reaction.reply, vec![ack()]);
    assert_eq!(codec.encode(&reaction.reply[0]).unwrap(), ACK);
    assert!(connection.ready());
}

#[test]
fn effective() {
    let wanted = Settings {
        window: 1000,
        frame: 32_768,
        ..Settings::default()
    };
    let (mut connection, _) = Connection::start(wanted).unwrap();
    connection.receive(&settings(&[])).unwrap();
    connection.send(&Stream(1).headers(false)).unwrap();
    assert_eq!(connection.flow().incoming(1), Some(65_535));
    assert!(
        connection
            .inbound()
            .encode(&Stream(1).data(20_000, false))
            .is_err()
    );
    let (frame, _) = Codec::default().decode(&ACK).unwrap().unwrap();
    connection.receive(&frame).unwrap();
    assert_eq!(connection.local().window, 1000);
    assert_eq!(connection.unacknowledged(), 0);
    assert_eq!(connection.flow().incoming(1), Some(1000));
    assert_eq!(connection.flow().incoming(0), Some(65_535));
    assert!(
        connection
            .inbound()
            .encode(&Stream(1).data(20_000, false))
            .is_ok()
    );
}

#[test]
fn applied() {
    let mut connection = ready(&[(3, 2), (4, 100), (5, 20_000), (1, 0)]);
    assert_eq!(connection.remote().streams, Some(2));
    assert_eq!(connection.remote().table, 0);
    assert!(
        connection
            .outbound()
            .encode(&Stream(1).data(20_000, false))
            .is_ok()
    );
    assert!(
        connection
            .outbound()
            .encode(&Stream(1).data(20_001, false))
            .is_err()
    );
    connection.send(&Stream(1).headers(false)).unwrap();
    assert_eq!(connection.flow().outgoing(1), Some(100));
    assert_eq!(
        connection.send(&Stream(1).data(101, false)),
        Err(Misuse::Window)
    );
    connection.send(&Stream(1).data(100, false)).unwrap();
    assert_eq!(connection.flow().outgoing(0), Some(65_435));
}

#[test]
fn updated() {
    let mut connection = ready(&[(4, 10)]);
    connection.send(&Stream(1).headers(false)).unwrap();
    connection.send(&Stream(1).data(10, false)).unwrap();
    assert_eq!(
        connection.send(&Stream(1).data(1, false)),
        Err(Misuse::Window)
    );
    let bytes = [0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 5];
    feed(&mut connection, &bytes).unwrap();
    connection.send(&Stream(1).data(5, false)).unwrap();
    assert_eq!(
        connection.send(&Stream(1).data(1, false)),
        Err(Misuse::Window)
    );
    let wide = [0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    feed(&mut connection, &wide).unwrap();
    assert_eq!(connection.flow().outgoing(0), Some(65_535 - 15 + 256));
}

#[test]
fn limited() {
    let mut connection = ready(&[(3, 1)]);
    connection.send(&Stream(1).headers(false)).unwrap();
    assert_eq!(
        connection.send(&Stream(3).headers(false)),
        Err(Misuse::Limit)
    );
    assert_eq!(connection.streams().state(3), State::Idle);
    connection.send(&Stream(1).reset()).unwrap();
    connection.send(&Stream(3).headers(false)).unwrap();
    assert_eq!(connection.streams().active(), 1);
    assert_eq!(connection.flow().outgoing(1), None);
}

#[test]
fn unlimited() {
    let mut connection = ready(&[]);
    for stream in (1..=199).step_by(2) {
        connection.send(&Stream(stream).headers(false)).unwrap();
    }
    assert_eq!(connection.streams().active(), 100);
}

#[test]
fn proposals() {
    let (mut connection, _) = Connection::start(Settings::default()).unwrap();
    connection.receive(&settings(&[])).unwrap();
    connection.send(&settings(&[(4, 500)])).unwrap();
    connection.send(&settings(&[(3, 7)])).unwrap();
    assert_eq!(connection.unacknowledged(), 3);
    connection.receive(&ack()).unwrap();
    assert_eq!(connection.local().window, 65_535);
    connection.receive(&ack()).unwrap();
    assert_eq!(connection.local().window, 500);
    assert_eq!(connection.local().streams, None);
    connection.receive(&ack()).unwrap();
    assert_eq!(connection.local().streams, Some(7));
    assert_eq!(connection.local().window, 500);
    assert!(!connection.local().push);
}

#[test]
fn conversation() {
    let wanted = Settings {
        window: 4096,
        ..Settings::default()
    };
    let (mut connection, _) = Connection::start(wanted).unwrap();
    let server = [
        vec![0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2],
        vec![0, 0, 0, 4, 1, 0, 0, 0, 0],
    ]
    .concat();
    let reactions = feed(&mut connection, &server).unwrap();
    assert_eq!(reactions[0].reply, vec![ack()]);
    assert!(reactions[1].reply.is_empty());
    connection.send(&Stream(1).headers(false)).unwrap();
    connection.send(&Stream(1).data(5, true)).unwrap();
    assert_eq!(connection.streams().state(1), State::Local);
    let response = [
        vec![0, 0, 0, 1, 4, 0, 0, 0, 1],
        vec![0, 0, 3, 0, 1, 0, 0, 0, 1, b'o', b'k', b'!'],
    ]
    .concat();
    feed(&mut connection, &response).unwrap();
    assert_eq!(
        connection.streams().state(1),
        State::Closed(h2::Close::Finished)
    );
    assert_eq!(connection.flow().incoming(0), Some(65_535 - 3));
    assert_eq!(connection.flow().incoming(1), None);
    let frame = Frame::Window {
        stream: 0,
        increment: 3,
    };
    connection.send(&frame).unwrap();
    assert_eq!(connection.flow().incoming(0), Some(65_535));
}
