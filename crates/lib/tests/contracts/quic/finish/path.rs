use super::remote::session;
use quic::{Echo, Frame, Issued, Number, Path, Peers, Role, Short, Streams, Validity};
use std::net::UdpSocket;

const TOKEN: [u8; 8] = [7, 6, 5, 4, 3, 2, 1, 0];

fn pack(keys: &quic::Keys, dcid: &[u8], number: u64, payload: &[u8]) -> Vec<u8> {
    let written = Number::new(number, None).unwrap();
    let short = Short {
        spin: false,
        phase: false,
        dcid: dcid.to_vec(),
        offset: 0,
    };
    keys.protect(number, &short.write(&written).unwrap(), payload)
        .unwrap()
}

fn take(socket: &UdpSocket, keys: &quic::Keys, local: usize) -> Vec<Frame> {
    let mut buf = [0u8; 2048];
    let used = socket.recv(&mut buf).unwrap();
    let payload = keys
        .unprotect(&buf[..used], 1 + local, None)
        .unwrap()
        .payload;
    Frame::all(&payload).unwrap()
}

#[test]
fn loopback() {
    let session = session();
    let mut client = Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024);
    let mut server = Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024);
    let id = client.open().unwrap();
    assert_eq!(client.write(id, b"ping").unwrap(), 4);
    client.finish(id).unwrap();
    let first = client.next(id, 1200).unwrap().unwrap();
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            0,
            &Frame::join(&[first]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(id, 16).unwrap(), b"ping");
    let mut path = Path::new(1_000);
    let probe = path.challenge(1, TOKEN, 64).unwrap();
    assert!(!probe.expand);
    assert_eq!(path.validity(), Validity::Pending);
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            1,
            &Frame::join(&[Frame::Challenge(probe.token)]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    let Frame::Challenge(token) = frames[0] else {
        panic!("{:?}", frames[0]);
    };
    let mut echo = Echo::default();
    assert!(echo.challenge(token));
    let reply = echo.next(64).unwrap();
    session
        .peer
        .send(&pack(
            &session.applied.server,
            &session.client,
            0,
            &Frame::join(&[Frame::Response(reply.token)]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.near, &session.applied.server, session.client.len());
    let Frame::Response(token) = frames[0] else {
        panic!("{:?}", frames[0]);
    };
    assert!(path.response(token));
    assert_eq!(path.validity(), Validity::Valid);
}

#[test]
fn issued() {
    let session = session();
    let mut client = Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024);
    let mut server = Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024);
    let id = client.open().unwrap();
    assert_eq!(client.write(id, b"ping").unwrap(), 4);
    client.finish(id).unwrap();
    let first = client.next(id, 1200).unwrap().unwrap();
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            0,
            &Frame::join(&[first]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(id, 16).unwrap(), b"ping");
    let mut issued = Issued::new(session.client.clone(), 8);
    let token = [9u8; 16];
    let fresh = vec![3u8; 8];
    let frame = issued.issue(fresh.clone(), token, 0).unwrap();
    let Frame::Issue {
        sequence,
        retire,
        cid,
        token: held,
    } = &frame
    else {
        panic!("{frame:?}");
    };
    assert_eq!((*sequence, *retire), (1, 0));
    assert_eq!((cid.as_slice(), *held), (fresh.as_slice(), token));
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            1,
            &Frame::join(&[frame]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    let Frame::Issue {
        sequence,
        retire,
        cid,
        token: held,
    } = &frames[0]
    else {
        panic!("{:?}", frames[0]);
    };
    assert_eq!((*sequence, *retire), (1, 0));
    assert_eq!((cid.as_slice(), *held), (fresh.as_slice(), token));
    let mut peers = Peers::new(session.client.clone(), None, 8);
    assert!(peers.receive(*sequence, *retire, cid, *held).is_ok());
    assert_eq!(peers.fresh(), Some((1, fresh)));
}
