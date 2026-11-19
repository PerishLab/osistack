use crate::data::*;
use crate::support::*;
use quic::Frame;

#[test]
fn initial() {
    let frame = hex(INITIAL);
    assert_eq!(frame.len(), 245);
    let mut payload = frame.clone();
    payload.resize(1162, 0);
    let expected = vec![
        Frame::Crypto {
            offset: 0,
            data: frame[4..].to_vec(),
        },
        Frame::Padding(917),
    ];
    assert_eq!(frame[..4], hex("060040f1"));
    assert_eq!(frame[4..].len(), 241);
    assert_eq!(Frame::all(&payload).unwrap(), expected);
    assert_eq!(Frame::join(&expected).unwrap(), payload);
}

#[test]
fn server() {
    let payload = hex(SERVER);
    assert_eq!(payload.len(), 99);
    let expected = vec![
        Frame::Ack(ack(0, 0, 0, &[])),
        Frame::Crypto {
            offset: 0,
            data: payload[9..].to_vec(),
        },
    ];
    assert_eq!(payload[9..].len(), 90);
    assert_eq!(Frame::all(&payload).unwrap(), expected);
    assert_eq!(Frame::join(&expected).unwrap(), payload);
}

#[test]
fn short() {
    assert_eq!(Frame::all(&hex("01")).unwrap(), vec![Frame::Ping]);
    assert_eq!(Frame::join(&[Frame::Ping]).unwrap(), hex("01"));
}
