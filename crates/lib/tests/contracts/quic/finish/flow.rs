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
    let mut client = Streams::new(Role::Client, 8, 8, 8);
    let mut server = Streams::new(Role::Server, 8, 8, 8);
    let id = client.open().unwrap();
    assert_eq!(client.write(id, b"abcdefghijklmnop").unwrap(), 16);
    client.finish(id).unwrap();
    let first = client.next(id, 1200).unwrap().unwrap();
    let Frame::Stream(stream) = &first else {
        panic!("{first:?}");
    };
    assert_eq!(stream.data.as_slice(), b"abcdefgh");
    assert!(!stream.fin);
    assert!(client.next(id, 1200).unwrap().is_none());
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
    assert_eq!(server.read(id, 16).unwrap(), b"abcdefgh");
    let credit = server.grant();
    assert!(
        credit.iter().any(|frame| matches!(frame, Frame::Data(16))),
        "{credit:?}"
    );
    assert!(
        credit.iter().any(|frame| matches!(
            frame,
            Frame::Window {
                stream,
                limit: 16
            } if *stream == id
        )),
        "{credit:?}"
    );
    session
        .peer
        .send(&pack(
            &session.applied.server,
            &session.client,
            0,
            &Frame::join(&credit).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    let second = client.next(id, 1200).unwrap().unwrap();
    let Frame::Stream(stream) = &second else {
        panic!("{second:?}");
    };
    assert_eq!(stream.data.as_slice(), b"ijklmnop");
    assert!(stream.fin);
    session
        .near
        .send(&pack(
            &session.applied.client,
            &session.server,
            1,
            &Frame::join(&[second]).unwrap(),
        ))
        .unwrap();
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    server.ingest(&frames).unwrap();
    assert_eq!(server.read(id, 16).unwrap(), b"ijklmnop");
}
