use super::remote::session;
use quic::{Frame, Number, Role, Short, Streams};
use std::net::UdpSocket;

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
    let first = client.next(id, 1200).unwrap().unwrap();
    let Frame::Stream(stream) = &first else {
        panic!("{first:?}");
    };
    assert!(!stream.fin);
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
    let reset = client.reset(id, 7).unwrap().unwrap();
    let Frame::Reset { stream, code, size } = reset else {
        panic!("{reset:?}");
    };
    assert_eq!((stream, code, size), (id, 7, 4));
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            1,
            &Frame::join(&[reset]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.broken(id).unwrap(), Some(7));
}
