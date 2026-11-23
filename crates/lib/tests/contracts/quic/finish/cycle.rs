use super::remote::session;
use quic::{Cycle, Frame, Number, Role, Short, Streams};
use std::net::UdpSocket;

fn pack(cycle: &Cycle, dcid: &[u8], number: u64, payload: &[u8]) -> Vec<u8> {
    let written = Number::new(number, None).unwrap();
    let short = Short {
        spin: false,
        phase: cycle.phase(),
        dcid: dcid.to_vec(),
        offset: 0,
    };
    cycle
        .protect(number, &short.write(&written).unwrap(), payload)
        .unwrap()
}

fn take(socket: &UdpSocket, cycle: &Cycle, local: usize) -> Vec<Frame> {
    let mut buf = [0u8; 2048];
    let used = socket.recv(&mut buf).unwrap();
    let payload = cycle
        .unprotect(&buf[..used], 1 + local, None)
        .unwrap()
        .payload;
    Frame::all(&payload).unwrap()
}

fn fresh() -> Streams {
    Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024)
}

fn peer() -> Streams {
    Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024)
}

#[test]
fn loopback() {
    let session = session();
    let mut client = fresh();
    let mut server = peer();
    let mut near = Cycle::new(session.applied.client.clone());
    let mut far = Cycle::new(session.applied.client.clone());
    let mut reply = Cycle::new(session.applied.server.clone());
    let mut back = Cycle::new(session.applied.server.clone());
    let early = client.open().unwrap();
    assert_eq!(client.write(early, b"ping").unwrap(), 4);
    client.finish(early).unwrap();
    let first = client.next(early, 1200).unwrap().unwrap();
    session
        .near
        .send(&pack(
            &near,
            &session.server,
            0,
            &Frame::join(&[first]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &far, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(early, 16).unwrap(), b"ping");
    near.advance().unwrap();
    far.advance().unwrap();
    reply.advance().unwrap();
    back.advance().unwrap();
    assert!(near.phase());
    let late = client.open().unwrap();
    assert_eq!(late, 4);
    assert_eq!(client.write(late, b"more").unwrap(), 4);
    client.finish(late).unwrap();
    let second = client.next(late, 1200).unwrap().unwrap();
    session
        .near
        .send(&pack(
            &near,
            &session.server,
            1,
            &Frame::join(&[second]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &far, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(late, 16).unwrap(), b"more");
    assert_eq!(server.write(late, b"back").unwrap(), 4);
    server.finish(late).unwrap();
    let third = server.next(late, 1200).unwrap().unwrap();
    session
        .peer
        .send(&pack(
            &reply,
            &session.client,
            0,
            &Frame::join(&[third]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.near, &back, session.client.len());
    client.ingest(&frames).unwrap();
    assert_eq!(client.read(late, 16).unwrap(), b"back");
}
