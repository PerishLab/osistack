use crate::support::*;
use crate::vectors::REQUESTS;
use h2::{Code, Connection, Fault, Frame, Misuse, Settings};

const PROTOCOL: Fault = Fault::Connection {
    code: Code::Protocol,
};
const CALM: Fault = Fault::Connection { code: Code::Calm };
const COMPRESSION: Fault = Fault::Connection {
    code: Code::Compression,
};

fn started() -> Connection {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    connection
}

#[test]
fn interrupted() {
    let others = [
        Stream(1).data(1, false),
        Stream(1).window(1),
        Stream(3).reset(),
        settings(&[]),
        ack(),
        Frame::Ping {
            ack: false,
            data: [0; 8],
        },
        Frame::Goaway {
            last: 0,
            code: 0,
            debug: Vec::new(),
        },
        full(3, "82", true),
        more(3, "82", true),
        Frame::Unknown {
            kind: 99,
            flags: 0,
            stream: 0,
            payload: Vec::new(),
        },
    ];
    for frame in others {
        let mut connection = started();
        connection.receive(&opening(1, "82")).unwrap();
        assert_eq!(connection.receive(&frame), Err(PROTOCOL), "{frame:?}");
    }
}

#[test]
fn stray() {
    let mut connection = started();
    assert_eq!(connection.receive(&more(1, "82", true)), Err(PROTOCOL));
    let mut done = started();
    done.receive(&full(1, "82", false)).unwrap();
    assert_eq!(done.receive(&more(1, "82", true)), Err(PROTOCOL));
}

#[test]
fn oversize() {
    let wanted = Settings {
        header: Some(64),
        ..Settings::default()
    };
    let (mut connection, _) = Connection::start(wanted);
    connection.receive(&settings(&[])).unwrap();
    connection.receive(&ack()).unwrap();
    connection.send(&Stream(1).headers(false)).unwrap();
    let exact = "82".repeat(64);
    assert!(connection.receive(&opening(1, &exact)).is_ok());
    let mut split = connection.clone();
    assert_eq!(connection.receive(&more(1, "82", true)), Err(CALM));
    split.receive(&more(1, "", true)).unwrap();
    split.send(&Stream(3).headers(false)).unwrap();
    split.receive(&opening(3, &"82".repeat(40))).unwrap();
    let rest = more(3, &"82".repeat(25), true);
    assert_eq!(split.receive(&rest), Err(CALM));
    assert_eq!(Code::Calm.get(), 0xb);
}

#[test]
fn unlimited() {
    let mut connection = started();
    let chunk = "82".repeat(16_384);
    connection.receive(&opening(1, &chunk)).unwrap();
    for _ in 0..15 {
        connection.receive(&more(1, &chunk, false)).unwrap();
    }
    assert_eq!(connection.receive(&more(1, "82", false)), Err(CALM));
}

#[test]
fn corrupt() {
    let mut connection = started();
    assert_eq!(connection.receive(&full(1, "80", true)), Err(COMPRESSION));
    let mut split = started();
    split.receive(&opening(1, "82")).unwrap();
    assert_eq!(split.receive(&more(1, "80", true)), Err(COMPRESSION));
    assert_eq!(Code::Compression.get(), 9);
}

#[test]
fn sending() {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    assert_eq!(connection.send(&more(1, "", true)), Err(Misuse::Block));
    let begin = Frame::Headers {
        stream: 3,
        fin: false,
        complete: false,
        pad: None,
        priority: None,
        block: bytes("82"),
    };
    connection.send(&begin).unwrap();
    let others = [
        Stream(3).data(1, false),
        Stream(1).data(1, false),
        Stream(3).window(1),
        settings(&[]),
        Stream(1).reset(),
        more(1, "", true),
        begin.clone(),
        Frame::Ping {
            ack: false,
            data: [0; 8],
        },
    ];
    for frame in others {
        assert_eq!(connection.send(&frame), Err(Misuse::Block), "{frame:?}");
    }
    assert_eq!(connection.headers(5, &[], false), Err(Misuse::Block));
    connection.send(&more(3, "", true)).unwrap();
    connection.send(&Stream(3).data(1, false)).unwrap();
}

#[test]
fn untouched() {
    let list = fields(&[("x-key", "value")]);
    let mut connection = ready(&[(3, 0)]);
    assert_eq!(connection.headers(1, &list, false), Err(Misuse::Limit));
    assert_eq!(connection.encoder().size(), 0);
    let mut other = ready(&[]);
    assert_eq!(other.headers(2, &list, false), Err(Misuse::Parity));
    assert_eq!(other.headers(0, &list, false), Err(Misuse::Zero));
    assert_eq!(other.encoder().size(), 0);
    other.headers(1, &list, false).unwrap();
    assert_eq!(other.encoder().size(), 42);
}

#[test]
fn rejected() {
    let mut connection = started();
    let first = connection.receive(&full(1, REQUESTS[0].hex, true)).unwrap();
    assert!(first.block.is_some());
    let second = connection.receive(&full(1, REQUESTS[1].hex, true));
    let fault = Fault::Stream {
        stream: 1,
        code: Code::Closed,
    };
    assert_eq!(second, Err(fault));
    assert_eq!(connection.decoder().size(), 110);
    connection.send(&Stream(3).headers(false)).unwrap();
    connection.send(&Stream(3).reset()).unwrap();
    let dropped = connection.receive(&full(3, REQUESTS[2].hex, true)).unwrap();
    assert_eq!(dropped.outcome, h2::Outcome::Discard);
    assert!(dropped.block.is_none());
    assert_eq!(connection.decoder().size(), 164);
}
