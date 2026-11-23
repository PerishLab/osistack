use quic::{Frame, Header, Initial, Opening, Param, Params};
use tls::{Extension, Hello, Kind, Message, Share};

fn share() -> Share {
    Share {
        group: 0x001d,
        key: vec![1; 32],
    }
}

fn params(scid: &[u8]) -> Params {
    Params {
        list: vec![Param::Idle(30_000), Param::Source(scid.to_vec())],
    }
}

fn hello(scid: &[u8]) -> Hello {
    let base = Hello::start(b"example.test", &[b"h3".to_vec()], share(), [7u8; 32]).unwrap();
    let mut offer = base.offer().clone();
    offer.extensions.push(Extension {
        kind: 0x39,
        data: params(scid).write().unwrap(),
    });
    let message = Message {
        kind: Kind::Offer,
        body: offer.write().unwrap(),
    };
    Hello::offered(&message.write().unwrap()).unwrap()
}

fn opening(dcid: &[u8], scid: &[u8]) -> Opening {
    Opening {
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: Vec::new(),
    }
}

#[test]
fn writes() {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let scid = [9u8; 4];
    let hello = hello(&scid);
    let packet = opening(&dcid, &scid).write(hello.spoken()).unwrap();
    assert!(packet.len() >= 1200);
    let Header::Long(long) = Header::parse(&packet, 8).unwrap() else {
        panic!("not long");
    };
    assert_eq!(
        (long.dcid, long.scid, long.token),
        (dcid.to_vec(), scid.to_vec(), Vec::new())
    );
    let opened = Initial::new(&dcid)
        .unwrap()
        .client
        .unprotect(&packet, long.offset, None)
        .unwrap();
    assert_eq!(opened.number, 0);
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { offset, data } = &frames[0] else {
        panic!("not crypto");
    };
    assert_eq!((*offset, data.as_slice()), (0, hello.spoken()));
    let offered = Hello::offered(data).unwrap();
    assert_eq!(offered.offer(), hello.offer());
    let found = offered
        .offer()
        .extensions
        .iter()
        .find(|item| item.kind == 0x39)
        .unwrap();
    assert_eq!(Params::parse(&found.data).unwrap(), params(&scid));
}

#[test]
fn refused() {
    let dcid = [1u8; 8];
    let scid = [2u8; 4];
    assert!(matches!(
        opening(&dcid, &scid).write(&[]),
        Err(quic::Error::Length)
    ));
}
