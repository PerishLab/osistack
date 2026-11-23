use super::remote::{Session, session};
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

fn peek(keys: &quic::Keys, packet: &[u8], local: usize) -> Vec<Frame> {
    let payload = keys.unprotect(packet, 1 + local, None).unwrap().payload;
    Frame::all(&payload).unwrap()
}

fn emit(socket: &UdpSocket, keys: &quic::Keys, dcid: &[u8], frame: Frame) {
    let payload = Frame::join(&[frame]).unwrap();
    socket.send(&pack(keys, dcid, 0, &payload)).unwrap();
}

fn take(socket: &UdpSocket, keys: &quic::Keys, local: usize) -> Vec<Frame> {
    let mut buf = [0u8; 2048];
    let used = socket.recv(&mut buf).unwrap();
    peek(keys, &buf[..used], local)
}

fn fresh() -> Streams {
    Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024)
}

fn peer() -> Streams {
    Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024)
}

fn wired(session: &Session) {
    let mut client = fresh();
    let mut server = peer();
    let id = client.open().unwrap();
    assert_eq!(id, 0);
    assert_eq!(client.write(id, b"ping").unwrap(), 4);
    client.finish(id).unwrap();
    let frame = client.next(id, 1200).unwrap().unwrap();
    emit(
        &session.near,
        &session.applied.client,
        &session.server,
        frame,
    );
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(id, 16).unwrap(), b"ping");
    assert_eq!(server.write(id, b"pong").unwrap(), 4);
    server.finish(id).unwrap();
    let frame = server.next(id, 1200).unwrap().unwrap();
    emit(
        &session.peer,
        &session.applied.server,
        &session.client,
        frame,
    );
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    assert_eq!(client.read(id, 16).unwrap(), b"pong");
}

#[test]
fn writes() {
    let mut client = fresh();
    let id = client.open().unwrap();
    assert_eq!(client.write(id, b"hello").unwrap(), 5);
    client.finish(id).unwrap();
    let Frame::Stream(stream) = client.next(id, 1200).unwrap().unwrap() else {
        panic!("not stream");
    };
    assert_eq!(stream.id, 0);
    assert_eq!(stream.offset, 0);
    assert_eq!(stream.data, b"hello");
    assert!(stream.fin);
    let mut server = peer();
    server.ingest(&[Frame::Stream(stream)]).unwrap();
    assert_eq!(server.read(id, 16).unwrap(), b"hello");
}

#[test]
fn loopback() {
    wired(&session());
}

#[test]
fn many() {
    let session = session();
    let mut client = fresh();
    let mut server = peer();
    let one = client.open().unwrap();
    let two = client.open().unwrap();
    assert_eq!((one, two), (0, 4));
    assert_eq!(client.write(one, b"ping").unwrap(), 4);
    client.finish(one).unwrap();
    assert_eq!(client.write(two, b"pang").unwrap(), 4);
    client.finish(two).unwrap();
    let first = client.next(one, 1200).unwrap().unwrap();
    let second = client.next(two, 1200).unwrap().unwrap();
    let payload = Frame::join(&[first, second]).unwrap();
    session
        .near
        .send(&pack(&session.applied.client, &session.server, 0, &payload))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(one, 16).unwrap(), b"ping");
    assert_eq!(server.read(two, 16).unwrap(), b"pang");
    assert_eq!(server.write(one, b"pong").unwrap(), 4);
    server.finish(one).unwrap();
    assert_eq!(server.write(two, b"peng").unwrap(), 4);
    server.finish(two).unwrap();
    let first = server.next(one, 1200).unwrap().unwrap();
    let second = server.next(two, 1200).unwrap().unwrap();
    let payload = Frame::join(&[first, second]).unwrap();
    session
        .peer
        .send(&pack(&session.applied.server, &session.client, 0, &payload))
        .unwrap();
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    assert_eq!(client.read(one, 16).unwrap(), b"pong");
    assert_eq!(client.read(two, 16).unwrap(), b"peng");
}

#[test]
fn probe() {
    let session = session();
    let mut client = fresh();
    let mut server = peer();
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
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            1,
            &Frame::join(&[Frame::Ping, Frame::Padding(16)]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    assert_eq!(frames[0], Frame::Ping);
}
