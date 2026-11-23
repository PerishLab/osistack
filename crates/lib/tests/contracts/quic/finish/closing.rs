use super::remote::session;
use quic::{Control, Frame, Number, Role, Short, Streams};
use std::net::UdpSocket;

fn pack(keys: &quic::Keys, dcid: &[u8], payload: &[u8]) -> Vec<u8> {
    let written = Number::new(0, None).unwrap();
    let short = Short {
        spin: false,
        phase: false,
        dcid: dcid.to_vec(),
        offset: 0,
    };
    keys.protect(0, &short.write(&written).unwrap(), payload)
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
    let stream = client.next(id, 1200).unwrap().unwrap();
    let mut control = Control::new(25_000, 3);
    let close = control.close(1, 0, 0, b"done").unwrap();
    let payload = Frame::join(&[stream, close]).unwrap();
    session
        .near
        .send(&pack(&session.applied.client, &session.server, &payload))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(id, 16).unwrap(), b"ping");
    let Frame::Transport {
        code,
        frame,
        reason,
    } = &frames[1]
    else {
        panic!("{:?}", frames[1]);
    };
    assert_eq!(
        (*code, *frame, reason.as_slice()),
        (0, 0, b"done".as_slice())
    );
}
