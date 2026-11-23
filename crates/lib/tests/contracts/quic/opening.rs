use quic::{Frame, Header, Initial, Opening, Param, Params, Retry};
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

fn hello(scid: &[u8], random: [u8; 32]) -> Hello {
    let base = Hello::start(b"example.test", &[b"h3".to_vec()], share(), random).unwrap();
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
    let hello = hello(&scid, [7u8; 32]);
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

fn later(scid: &[u8]) -> Hello {
    hello(scid, [8u8; 32])
}

fn retrying(odcid: &[u8], client: &[u8], server: &[u8], token: &[u8]) -> Retry {
    let mut retry = Retry {
        unused: 0,
        dcid: client.to_vec(),
        scid: server.to_vec(),
        token: token.to_vec(),
        tag: [0; 16],
    };
    retry.fill(odcid).unwrap();
    retry
}

#[test]
fn retries() {
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = [9u8; 4];
    let server = [4u8; 8];
    let retry = retrying(&odcid, &client, &server, b"token");
    let hello = later(&client);
    let packet = opening(&odcid, &client)
        .retry(&retry, hello.spoken())
        .unwrap();
    assert!(packet.len() >= 1200);
    let Header::Long(long) = Header::parse(&packet, 8).unwrap() else {
        panic!("not long");
    };
    assert_eq!(
        (long.dcid, long.scid, long.token),
        (server.to_vec(), client.to_vec(), b"token".to_vec())
    );
    let opened = Initial::new(&server)
        .unwrap()
        .client
        .unprotect(&packet, long.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { data, .. } = &frames[0] else {
        panic!("not crypto");
    };
    assert_eq!(data.as_slice(), hello.spoken());
}

#[test]
fn rejected() {
    let odcid = [1u8; 8];
    let client = [2u8; 4];
    let server = [3u8; 8];
    let hello = later(&client);
    let empty = Retry {
        unused: 0,
        dcid: client.to_vec(),
        scid: server.to_vec(),
        token: Vec::new(),
        tag: [0; 16],
    };
    assert!(matches!(
        opening(&odcid, &client).retry(&empty, hello.spoken()),
        Err(quic::Error::Empty)
    ));
    let mut bad = retrying(&odcid, &client, &server, b"token");
    bad.tag[0] ^= 1;
    assert!(
        opening(&odcid, &client)
            .retry(&bad, hello.spoken())
            .is_err()
    );
}

pub fn retry() {
    use std::net::UdpSocket;
    use std::time::Duration;
    let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = [9u8; 4];
    let server = [4u8; 8];
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let near = UdpSocket::bind("127.0.0.1:0").unwrap();
    near.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    near.connect(peer.local_addr().unwrap()).unwrap();
    let first = hello(&client, [7u8; 32]);
    near.send(&opening(&odcid, &client).write(first.spoken()).unwrap())
        .unwrap();
    let mut buf = [0u8; 2048];
    let (used, from) = peer.recv_from(&mut buf).unwrap();
    let Header::Long(long) = Header::parse(&buf[..used], 8).unwrap() else {
        panic!("not long");
    };
    assert_eq!(long.dcid, odcid);
    let retry = retrying(&odcid, &long.scid, &server, b"token");
    peer.send_to(&retry.write().unwrap(), from).unwrap();
    let (used, _) = near.recv_from(&mut buf).unwrap();
    let Header::Retry(got) = Header::parse(&buf[..used], 0).unwrap() else {
        panic!("not retry");
    };
    let later = later(&client);
    near.send(
        &opening(&odcid, &client)
            .retry(&got, later.spoken())
            .unwrap(),
    )
    .unwrap();
    let (used, _) = peer.recv_from(&mut buf).unwrap();
    let Header::Long(long) = Header::parse(&buf[..used], 8).unwrap() else {
        panic!("not long");
    };
    assert_eq!(
        (long.dcid, long.scid, long.token),
        (server.to_vec(), client.to_vec(), b"token".to_vec())
    );
    let opened = Initial::new(&server)
        .unwrap()
        .client
        .unprotect(&buf[..used], long.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { data, .. } = &frames[0] else {
        panic!("not crypto");
    };
    assert_eq!(data.as_slice(), later.spoken());
    assert_ne!(later.spoken(), first.spoken());
}
