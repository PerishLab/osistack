use crate::support::*;
use h2::{Code, Connection, Fault, Frame, Misuse, Outcome, Settings, State};

const PROTOCOL: Fault = Fault::Connection {
    code: Code::Protocol,
};
const FLOW: Fault = Fault::Connection { code: Code::Flow };

fn fresh() -> Connection {
    Connection::start(Settings::default()).unwrap().0
}

#[test]
fn first() {
    let ping = Frame::Ping {
        ack: false,
        data: [0; 8],
    };
    for frame in [
        Stream(1).data(1, false),
        Stream(1).headers(false),
        ack(),
        Stream(0).window(1),
        ping,
        Stream(1).reset(),
    ] {
        let mut connection = fresh();
        assert_eq!(connection.receive(&frame), Err(PROTOCOL));
        assert!(!connection.ready());
    }
}

#[test]
fn pushed() {
    for value in [1, 2] {
        let mut connection = fresh();
        assert_eq!(connection.receive(&settings(&[(2, value)])), Err(PROTOCOL));
        assert!(!connection.ready());
    }
    let mut connection = fresh();
    connection.receive(&settings(&[(2, 0)])).unwrap();
}

#[test]
fn values() {
    let cases = [
        (vec![(5, 16_383)], PROTOCOL),
        (vec![(5, 0x100_0000)], PROTOCOL),
        (vec![(4, 0x8000_0000)], FLOW),
    ];
    for (list, fault) in cases {
        let mut connection = fresh();
        assert_eq!(connection.receive(&settings(&list)), Err(fault));
        assert!(!connection.ready());
        assert_eq!(connection.remote(), &Settings::default());
    }
}

#[test]
fn atomic() {
    let mut connection = ready(&[(3, 5)]);
    let broken = settings(&[(3, 9), (5, 1)]);
    assert_eq!(connection.receive(&broken), Err(PROTOCOL));
    assert_eq!(connection.remote().streams, Some(5));
}

#[test]
fn extra() {
    let mut connection = ready(&[]);
    assert_eq!(connection.receive(&ack()), Err(PROTOCOL));
    assert_eq!(connection.unacknowledged(), 0);
}

#[test]
fn overflow() {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    let credit = Stream(1).window(0x7fff_ffff - 65_535);
    connection.receive(&credit).unwrap();
    assert_eq!(connection.flow().outgoing(1), Some(0x7fff_ffff));
    let wide = settings(&[(4, 0x7fff_ffff)]);
    let before = (connection.remote().clone(), connection.flow().outgoing(1));
    assert_eq!(connection.receive(&wide), Err(FLOW));
    assert_eq!(
        (connection.remote().clone(), connection.flow().outgoing(1)),
        before
    );
}

#[test]
fn outbound() {
    let mut connection = ready(&[]);
    assert_eq!(
        connection.send(&Stream(1).data(1, false)),
        Err(Misuse::Idle)
    );
    assert_eq!(connection.send(&Stream(1).window(1)), Err(Misuse::Idle));
    assert_eq!(
        connection.send(&Stream(2).headers(false)),
        Err(Misuse::Parity)
    );
    assert_eq!(connection.send(&ack()), Err(Misuse::Setting));
    assert_eq!(connection.send(&settings(&[(2, 1)])), Err(Misuse::Setting));
    assert_eq!(connection.send(&settings(&[(5, 1)])), Err(Misuse::Setting));
    assert_eq!(connection.unacknowledged(), 0);
    connection.send(&Stream(1).headers(true)).unwrap();
    assert_eq!(
        connection.send(&Stream(1).data(1, false)),
        Err(Misuse::Half)
    );
    assert_eq!(connection.flow().outgoing(1), Some(65_535));
    assert_eq!(
        connection.send(&Stream(0).window(0)),
        Err(Misuse::Increment)
    );
}

#[test]
fn exhausted() {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    connection.send(&Stream(1).data(65_535, false)).unwrap();
    assert_eq!(
        connection.send(&Stream(1).data(1, false)),
        Err(Misuse::Window)
    );
    assert_eq!(connection.streams().state(1), State::Open);
    connection.send(&Stream(1).data(0, true)).unwrap();
    assert_eq!(connection.streams().state(1), State::Local);
}

#[test]
fn inbound() {
    let mut connection = ready(&[]);
    assert_eq!(connection.receive(&Stream(1).window(1)), Err(PROTOCOL));
    connection.send(&Stream(1).headers(false)).unwrap();
    let big = Stream(1).data(65_535, false);
    assert_eq!(connection.receive(&big).unwrap().outcome, Outcome::Accept);
    let more = Stream(1).data(1, false);
    assert_eq!(connection.receive(&more), Err(FLOW));
}

#[test]
fn lone() {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    connection.send(&Stream(3).headers(false)).unwrap();
    connection.send(&Stream(0).window(1000)).unwrap();
    connection.receive(&Stream(1).data(65_535, false)).unwrap();
    let fault = connection.receive(&Stream(1).data(1, false));
    assert_eq!(
        fault,
        Err(Fault::Stream {
            stream: 1,
            code: Code::Flow
        })
    );
    assert_eq!(connection.flow().incoming(0), Some(999));
}

#[test]
fn halved() {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    connection.receive(&Stream(1).headers(true)).unwrap();
    let fault = connection.receive(&Stream(1).data(4, false));
    assert_eq!(
        fault,
        Err(Fault::Stream {
            stream: 1,
            code: Code::Closed
        })
    );
    assert_eq!(connection.flow().incoming(0), Some(65_531));
}

#[test]
fn discarded() {
    let mut connection = ready(&[]);
    connection.send(&Stream(1).headers(false)).unwrap();
    connection.send(&Stream(1).reset()).unwrap();
    assert_eq!(connection.flow().incoming(1), None);
    let reaction = connection.receive(&Stream(1).data(40, false)).unwrap();
    assert_eq!(reaction.outcome, Outcome::Discard);
    assert_eq!(connection.flow().incoming(0), Some(65_495));
    let closed = connection.receive(&Stream(1).window(5)).unwrap();
    assert_eq!(closed.outcome, Outcome::Discard);
}
