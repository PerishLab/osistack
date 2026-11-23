use crate::quic::finish::session;
use h3::{Call, Decoder, Encoder, Event, Field, Request, Settings};
use quic::{Frame as Packet, Number, Role, Short, Streams};
use std::net::UdpSocket;

const LIMIT: usize = 1 << 16;

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

fn emit(socket: &UdpSocket, keys: &quic::Keys, dcid: &[u8], frames: &[Packet]) {
    let payload = Packet::join(frames).unwrap();
    socket.send(&pack(keys, dcid, &payload)).unwrap();
}

fn take(socket: &UdpSocket, keys: &quic::Keys, local: usize) -> Vec<Packet> {
    let mut buf = [0u8; 2048];
    let used = socket.recv(&mut buf).unwrap();
    let payload = keys
        .unprotect(&buf[..used], 1 + local, None)
        .unwrap()
        .payload;
    Packet::all(&payload).unwrap()
}

fn asked(method: &[u8], path: &[u8]) -> Vec<Field> {
    vec![
        Field::new(b":method", method),
        Field::new(b":path", path),
        Field::new(b":scheme", b"https"),
        Field::new(b":authority", b"example.test"),
    ]
}

fn replied() -> Vec<Field> {
    vec![
        Field::new(b":status", b"200"),
        Field::new(b"content-type", b"text/plain"),
    ]
}

fn stream(id: u64, data: &[u8], fin: bool) -> Packet {
    Packet::Stream(quic::Stream {
        id,
        offset: 0,
        data: data.to_vec(),
        fin,
        sized: true,
    })
}

fn headed(fields: &[Field], body: &[u8]) -> Vec<u8> {
    let mut reply = Request::new(LIMIT);
    let mut payload = reply.headers(&Encoder::new(true).encode(fields)).unwrap();
    payload.extend(reply.data(body).unwrap());
    reply.finish().unwrap();
    payload
}

fn opened(path: &[u8]) -> (Call, Vec<u8>) {
    let mut call = Call::new(LIMIT);
    let headers = call.headers(&asked(b"GET", path)).unwrap();
    call.finish().unwrap();
    (call, headers)
}

fn posted(path: &[u8], body: &[u8]) -> (Call, Vec<u8>) {
    let mut call = Call::new(LIMIT);
    let mut wire = call.headers(&asked(b"POST", path)).unwrap();
    wire.extend(call.data(body).unwrap());
    call.finish().unwrap();
    (call, wire)
}

fn pulled(call: &mut Call, bytes: &[u8]) -> (Vec<Field>, Vec<u8>) {
    let events = call.feed(bytes).unwrap();
    let mut status = None;
    let mut data = Vec::new();
    for event in events {
        match event {
            Event::Headers(block) => {
                status = Some(Decoder::new(0).decode(&block).unwrap());
            }
            Event::Data(part) => data.extend(part),
            _ => {}
        }
    }
    (status.unwrap(), data)
}

#[test]
fn loopback() {
    let session = session();
    let (mut first, one) = opened(b"/one");
    let (mut second, two) = opened(b"/two");
    let mut client = Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024);
    let early = client.open().unwrap();
    let late = client.open().unwrap();
    assert_eq!((early, late), (0, 4));
    assert_eq!(client.write(early, &one).unwrap(), one.len());
    client.finish(early).unwrap();
    assert_eq!(client.write(late, &two).unwrap(), two.len());
    client.finish(late).unwrap();
    let control = Call::control(&Settings::default()).unwrap();
    emit(
        &session.near,
        &session.applied.client,
        &session.server,
        &[
            stream(2, &control, true),
            client.next(early, 1200).unwrap().unwrap(),
            client.next(late, 1200).unwrap().unwrap(),
        ],
    );
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    let mut server = Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024);
    server.ingest(&frames).unwrap();
    let mut incoming = Request::new(LIMIT);
    let events = incoming.feed(&server.read(0, LIMIT).unwrap()).unwrap();
    let Event::Headers(block) = &events[0] else {
        panic!("headers");
    };
    assert_eq!(
        Decoder::new(0).decode(block).unwrap(),
        asked(b"GET", b"/one")
    );
    let mut incoming = Request::new(LIMIT);
    let events = incoming.feed(&server.read(4, LIMIT).unwrap()).unwrap();
    let Event::Headers(block) = &events[0] else {
        panic!("headers");
    };
    assert_eq!(
        Decoder::new(0).decode(block).unwrap(),
        asked(b"GET", b"/two")
    );
    let settings = Call::control(&Settings::default()).unwrap();
    emit(
        &session.peer,
        &session.applied.server,
        &session.client,
        &[
            stream(3, &settings, true),
            stream(0, &headed(&replied(), b"a"), true),
            stream(4, &headed(&replied(), b"b"), true),
        ],
    );
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    let (status, data) = pulled(&mut first, &client.read(0, LIMIT).unwrap());
    assert_eq!(status, replied());
    assert_eq!(data, b"a");
    assert_eq!(first.end(), Ok(Event::End));
    let (status, data) = pulled(&mut second, &client.read(4, LIMIT).unwrap());
    assert_eq!(status, replied());
    assert_eq!(data, b"b");
    assert_eq!(second.end(), Ok(Event::End));
}

#[test]
fn posting() {
    let session = session();
    let (mut call, wire) = posted(b"/path", b"hello");
    let mut client = Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024);
    let id = client.open().unwrap();
    assert_eq!(id, 0);
    assert_eq!(client.write(id, &wire).unwrap(), wire.len());
    client.finish(id).unwrap();
    let control = Call::control(&Settings::default()).unwrap();
    emit(
        &session.near,
        &session.applied.client,
        &session.server,
        &[
            stream(2, &control, true),
            client.next(id, 1200).unwrap().unwrap(),
        ],
    );
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    let mut server = Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024);
    server.ingest(&frames).unwrap();
    let events = Request::new(LIMIT)
        .feed(&server.read(0, LIMIT).unwrap())
        .unwrap();
    let Event::Headers(block) = &events[0] else {
        panic!("headers");
    };
    assert_eq!(
        Decoder::new(0).decode(block).unwrap(),
        asked(b"POST", b"/path")
    );
    let Event::Data(part) = &events[1] else {
        panic!("data: {events:?}");
    };
    assert_eq!(part, b"hello");
    let settings = Call::control(&Settings::default()).unwrap();
    emit(
        &session.peer,
        &session.applied.server,
        &session.client,
        &[
            stream(3, &settings, true),
            stream(0, &headed(&replied(), b"ok"), true),
        ],
    );
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    let (status, data) = pulled(&mut call, &client.read(0, LIMIT).unwrap());
    assert_eq!(status, replied());
    assert_eq!(data, b"ok");
    assert_eq!(call.end(), Ok(Event::End));
}
