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
    let stop = server.stop(id, 7).unwrap().unwrap();
    let Frame::Stop { stream, code } = stop else {
        panic!("{stop:?}");
    };
    assert_eq!((stream, code), (id, 7));
    session
        .peer
        .send(&pack(
            &session.applied.server,
            &session.client,
            0,
            &Frame::join(&[stop]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.near, &session.applied.server, session.client.len());
    let Frame::Stop { stream, code } = frames[0] else {
        panic!("{:?}", frames[0]);
    };
    assert_eq!((stream, code), (id, 7));
    client.ingest(&frames).unwrap();
    assert!(client.reset(id, 7).is_err());
}
