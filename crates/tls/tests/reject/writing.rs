use crate::support::*;
use tls::{Content, Error, Kind, Message, Offer, Record};

#[test]
fn offer() {
    let mut long = offered(vec![blob(1, 4)]);
    long.session = vec![0; 33];
    assert_eq!(long.write(), Err(Error::Length));
    let mut bare = offered(vec![blob(1, 4)]);
    bare.suites = Vec::new();
    assert_eq!(bare.write(), Err(Error::Suites));
    assert_eq!(offered(vec![blob(1, 2)]).write(), Err(Error::Length));
    assert_eq!(offered(Vec::new()).write(), Err(Error::Length));
    assert!(offered(vec![blob(1, 4)]).write().is_ok());
}

#[test]
fn reply() {
    let mut long = replied(vec![blob(1, 4)]);
    long.session = vec![0; 33];
    assert_eq!(long.write(), Err(Error::Length));
    assert_eq!(replied(vec![blob(1, 1)]).write(), Err(Error::Length));
    assert!(replied(vec![blob(1, 2)]).write().is_ok());
}

#[test]
fn extensions() {
    let big = offered(vec![blob(1, 65536)]);
    assert_eq!(big.write(), Err(Error::Length));
    let wide = offered(vec![blob(1, 65532)]);
    assert_eq!(wide.write(), Err(Error::Length));
    let edge = offered(vec![blob(1, 65531)]);
    let body = edge.write().unwrap();
    assert_eq!(Offer::parse(&body), Ok(edge));
    let many = offered(vec![
        blob(1, 20000),
        blob(2, 20000),
        blob(3, 20000),
        blob(4, 20000),
    ]);
    assert_eq!(many.write(), Err(Error::Length));
    let same = offered(vec![blob(1, 4), blob(1, 4)]);
    assert_eq!(same.write(), Err(Error::Duplicate));
    assert_eq!(
        replied(vec![blob(1, 4), blob(1, 0)]).write(),
        Err(Error::Duplicate)
    );
}

#[test]
fn framing() {
    let big = Message {
        kind: Kind::Offer,
        body: vec![0; 1 << 24],
    };
    assert_eq!(big.write(), Err(Error::Length));
    let edge = Message {
        kind: Kind::Offer,
        body: vec![0; (1 << 24) - 1],
    };
    assert_eq!(edge.write().unwrap().len(), 4 + (1 << 24) - 1);
    let record = Record {
        content: Content::Handshake,
        version: 0x0303,
        fragment: vec![0; 16641],
    };
    assert_eq!(record.write(), Err(Error::Length));
    let record = Record {
        fragment: vec![0; 16640],
        ..record
    };
    assert_eq!(record.write().unwrap().len(), 5 + 16640);
}
