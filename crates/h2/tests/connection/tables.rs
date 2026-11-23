use crate::support::*;
use crate::vectors::REQUESTS;
use h2::{Code, Codec, Connection, Decoder, Fault, Frame, Misuse, Settings};

fn joined(frames: &[Frame]) -> Vec<u8> {
    let mut block = Vec::new();
    for frame in frames {
        match frame {
            Frame::Headers { block: bytes, .. } | Frame::Continuation { block: bytes, .. } => {
                block.extend_from_slice(bytes)
            }
            other => panic!("{other:?}"),
        }
    }
    block
}

#[test]
fn shrunk() {
    let list = fields(&[(":method", "GET"), ("x-key", "value")]);
    let mut connection = ready(&[(1, 0)]);
    let block = joined(&connection.headers(1, &list, true).unwrap());
    assert_eq!(block[0], 0x20);
    let mut peer = Decoder::new(4096);
    assert_eq!(peer.decode(&block).unwrap(), list);
    assert_eq!(peer.size(), 0);
    assert_eq!(connection.encoder().size(), 0);
    let again = fields(&[(":method", "GET")]);
    let second = joined(&connection.headers(3, &again, true).unwrap());
    assert_eq!(second, vec![0x82]);
}

#[test]
fn unchanged() {
    let mut connection = ready(&[(1, 4096)]);
    let list = fields(&[(":method", "GET")]);
    let block = joined(&connection.headers(1, &list, true).unwrap());
    assert_eq!(block, vec![0x82]);
}

#[test]
fn acknowledged() {
    let wanted = Settings {
        table: 0,
        ..Settings::default()
    };
    let (mut connection, _) = Connection::start(wanted.clone()).unwrap();
    connection.receive(&settings(&[])).unwrap();
    connection.send(&Stream(1).headers(false)).unwrap();
    connection
        .receive(&full(1, REQUESTS[0].hex, false))
        .unwrap();
    assert_eq!(connection.decoder().size(), 57);
    connection.receive(&ack()).unwrap();
    assert_eq!(connection.decoder().size(), 0);
    assert!(connection.decoder().dynamic().is_empty());
    let update = full(1, "3fe11f82", false);
    let fault = Fault::Connection {
        code: Code::Compression,
    };
    assert_eq!(connection.receive(&update), Err(fault));
    let (mut early, _) = Connection::start(wanted).unwrap();
    early.receive(&settings(&[])).unwrap();
    early.send(&Stream(1).headers(false)).unwrap();
    assert!(early.receive(&update).unwrap().block.is_some());
}

#[test]
fn frames() {
    let list = fields(&[("x-big", &"a".repeat(100_000))]);
    for (most, size) in [(16_384, 16_384), (20_000, 20_000)] {
        let setting = [(5, most)];
        let mut connection = ready(if most == 16_384 { &[] } else { &setting });
        let frames = connection.headers(1, &list, false).unwrap();
        assert!(frames.len() > 2);
        let last = frames.len() - 1;
        for (at, frame) in frames.iter().enumerate() {
            let (block, complete) = match frame {
                Frame::Headers {
                    block, complete, ..
                } if at == 0 => (block, complete),
                Frame::Continuation {
                    block, complete, ..
                } if at > 0 => (block, complete),
                other => panic!("{other:?}"),
            };
            assert_eq!(*complete, at == last);
            assert_eq!(block.len() == size, at < last, "{most} {at}");
        }
        let codec = Codec::new(size).unwrap();
        assert!(wire(&codec, &frames).len() > 100);
    }
}

#[test]
fn window() {
    let mut connection = ready(&[(4, 100)]);
    connection.headers(1, &[], false).unwrap();
    connection.send(&Stream(1).data(100, false)).unwrap();
    let over = connection.send(&Stream(1).data(1, false));
    assert_eq!(over, Err(Misuse::Window));
    connection.receive(&settings(&[(4, 200)])).unwrap();
    connection.send(&Stream(1).data(100, false)).unwrap();
    let again = connection.send(&Stream(1).data(1, false));
    assert_eq!(again, Err(Misuse::Window));
}

#[test]
fn inbound() {
    let wanted = Settings {
        window: 100,
        ..Settings::default()
    };
    let (mut connection, _) = Connection::start(wanted).unwrap();
    connection.receive(&settings(&[])).unwrap();
    connection.receive(&ack()).unwrap();
    connection.headers(1, &[], false).unwrap();
    connection.receive(&Stream(1).headers(false)).unwrap();
    connection.receive(&Stream(1).data(100, false)).unwrap();
    let over = connection.receive(&Stream(1).data(1, false));
    let fault = Fault::Stream {
        stream: 1,
        code: Code::Flow,
    };
    assert_eq!(over, Err(fault));
}
