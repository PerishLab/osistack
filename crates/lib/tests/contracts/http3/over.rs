use crate::quic::finish::session;
use h3::{Call, Control, Decoder, Encoder, Event, Field, Notice, Request, Settings};
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

fn asked() -> Vec<Field> {
    vec![
        Field::new(b":method", b"GET"),
        Field::new(b":path", b"/index"),
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

fn body(frames: &[Packet], id: u64) -> Vec<u8> {
    let mut data = Vec::new();
    for frame in frames {
        if let Packet::Stream(item) = frame
            && item.id == id
        {
            data.extend_from_slice(&item.data);
        }
    }
    data
}

#[test]
fn encodes() {
    let mut call = Call::new(LIMIT);
    let wire = call.headers(&asked()).unwrap();
    call.finish().unwrap();
    let mut peer = Request::new(LIMIT);
    let events = peer.feed(&wire).unwrap();
    let Event::Headers(block) = &events[0] else {
        panic!("headers");
    };
    assert_eq!(Decoder::new(0).decode(block).unwrap(), asked());
}

#[test]
fn loopback() {
    let session = session();
    let mut call = Call::new(LIMIT);
    let control = Call::control(&Settings::default()).unwrap();
    let headers = call.headers(&asked()).unwrap();
    call.finish().unwrap();
    let mut client = Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024);
    let id = client.open().unwrap();
    assert_eq!(id, 0);
    assert_eq!(client.write(id, &headers).unwrap(), headers.len());
    client.finish(id).unwrap();
    let request = client.next(id, 1200).unwrap().unwrap();
    emit(
        &session.near,
        &session.applied.client,
        &session.server,
        &[stream(2, &control, true), request],
    );
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    let mut server = Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024);
    server.ingest(&frames).unwrap();
    let preface = body(&frames, 2);
    assert_eq!(preface[0], 0x00);
    let mut inbound = Control::new(LIMIT);
    let notices = inbound.feed(&preface[1..]).unwrap();
    assert_eq!(notices.len(), 1);
    let seen = server.read(0, LIMIT).unwrap();
    let mut incoming = Request::new(LIMIT);
    let events = incoming.feed(&seen).unwrap();
    let Event::Headers(block) = &events[0] else {
        panic!("headers");
    };
    assert_eq!(Decoder::new(0).decode(block).unwrap(), asked());
    let mut reply = Request::new(LIMIT);
    let mut payload = reply
        .headers(&Encoder::new(true).encode(&replied()))
        .unwrap();
    payload.extend(reply.data(b"ok").unwrap());
    reply.finish().unwrap();
    let settings = Call::control(&Settings::default()).unwrap();
    emit(
        &session.peer,
        &session.applied.server,
        &session.client,
        &[stream(3, &settings, true), stream(0, &payload, true)],
    );
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    let events = call.feed(&client.read(0, LIMIT).unwrap()).unwrap();
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
    assert_eq!(status.unwrap(), replied());
    assert_eq!(data, b"ok");
    assert_eq!(call.end(), Ok(Event::End));
}

#[test]
fn farewell() {
    let session = session();
    let mut call = Call::new(LIMIT);
    let control = Call::control(&Settings::default()).unwrap();
    let headers = call.headers(&asked()).unwrap();
    call.finish().unwrap();
    let mut client = Streams::new(Role::Client, 8, 64 * 1024, 64 * 1024);
    let id = client.open().unwrap();
    assert_eq!(client.write(id, &headers).unwrap(), headers.len());
    client.finish(id).unwrap();
    let request = client.next(id, 1200).unwrap().unwrap();
    emit(
        &session.near,
        &session.applied.client,
        &session.server,
        &[stream(2, &control, true), request],
    );
    let frames = take(&session.peer, &session.applied.client, session.server.len());
    let mut server = Streams::new(Role::Server, 8, 64 * 1024, 64 * 1024);
    server.ingest(&frames).unwrap();
    let mut incoming = Request::new(LIMIT);
    let events = incoming.feed(&server.read(0, LIMIT).unwrap()).unwrap();
    let Event::Headers(block) = &events[0] else {
        panic!("headers");
    };
    assert_eq!(Decoder::new(0).decode(block).unwrap(), asked());
    let mut reply = Request::new(LIMIT);
    let mut payload = reply
        .headers(&Encoder::new(true).encode(&replied()))
        .unwrap();
    payload.extend(reply.data(b"ok").unwrap());
    reply.finish().unwrap();
    let settings = Call::control(&Settings::default()).unwrap();
    emit(
        &session.peer,
        &session.applied.server,
        &session.client,
        &[stream(3, &settings, false), stream(0, &payload, true)],
    );
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    let events = call.feed(&client.read(0, LIMIT).unwrap()).unwrap();
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
    assert_eq!(status.unwrap(), replied());
    assert_eq!(data, b"ok");
    assert_eq!(call.end(), Ok(Event::End));
    let preface = client.read(3, LIMIT).unwrap();
    assert_eq!(preface[0], 0x00);
    let mut inbound = Control::new(LIMIT);
    let notices = inbound.feed(&preface[1..]).unwrap();
    assert!(
        notices
            .iter()
            .any(|notice| matches!(notice, Notice::Settings(_))),
        "{notices:?}"
    );
    let goaway = h3::Frame::Goaway(0).encode().unwrap();
    let next = Packet::Stream(quic::Stream {
        id: 3,
        offset: settings.len() as u64,
        data: goaway,
        fin: true,
        sized: true,
    });
    let written = Number::new(1, None).unwrap();
    let short = Short {
        spin: false,
        phase: false,
        dcid: session.client.clone(),
        offset: 0,
    };
    session
        .peer
        .send(
            &session
                .applied
                .server
                .protect(
                    1,
                    &short.write(&written).unwrap(),
                    &Packet::join(&[next]).unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
    let frames = take(&session.near, &session.applied.server, session.client.len());
    client.ingest(&frames).unwrap();
    let notices = inbound.feed(&client.read(3, LIMIT).unwrap()).unwrap();
    assert_eq!(notices, vec![Notice::Goaway(0)]);
}
