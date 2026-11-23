use super::{hello, shared};
use crate::tls::{mint, spoken};
use crypto::{Aead, Group, Hash};
use quic::{
    Applied, Flight, Frame, Handshake, Header, Hearing, Initial, Kind, Number, Opening, Short,
};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use tls::{Hello, Place, Typed};

fn socket() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    socket
}

fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 2048];
    let (used, from) = socket.recv_from(&mut buf).unwrap();
    (buf[..used].to_vec(), from)
}

fn share(hello: &Hello) -> Vec<u8> {
    let mut found = None;
    for item in &hello.offer().extensions {
        if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer).unwrap() {
            found = items.into_iter().next();
        }
    }
    found.unwrap().key
}

fn space(kind: Kind, dcid: &[u8], scid: &[u8]) -> Flight {
    Flight {
        kind,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: Vec::new(),
    }
}

fn protect(keys: &quic::Keys, dcid: &[u8], payload: &[u8]) -> Vec<u8> {
    let number = Number::new(0, None).unwrap();
    let short = Short {
        spin: false,
        phase: false,
        dcid: dcid.to_vec(),
        offset: 0,
    };
    keys.protect(0, &short.write(&number).unwrap(), payload)
        .unwrap()
}

fn open(keys: &quic::Keys, packet: &[u8], local: usize) -> Vec<u8> {
    keys.unprotect(packet, 1 + local, None).unwrap().payload
}

pub(super) struct Session {
    pub near: UdpSocket,
    pub peer: UdpSocket,
    pub applied: Applied,
    pub client: Vec<u8>,
    pub server: Vec<u8>,
}

pub(super) fn session() -> Session {
    let original = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = [9u8; 4];
    let server = [4u8; 8];
    let offered = [9u8; 32];
    let chosen = [8u8; 32];
    let hello = hello(&offered, &client);
    let held = mint("example.test");
    let peer = socket();
    let near = socket();
    near.connect(peer.local_addr().unwrap()).unwrap();
    let opening = Opening {
        dcid: original.to_vec(),
        scid: client.to_vec(),
        token: Vec::new(),
    }
    .write(hello.spoken())
    .unwrap();
    near.send(&opening).unwrap();
    let (packet, from) = recv(&peer);
    let Header::Long(long) = Header::parse(&packet, 0).unwrap() else {
        panic!("not long");
    };
    let opened = Initial::new(&long.dcid)
        .unwrap()
        .client
        .unprotect(&packet[..long.size().unwrap()], long.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { data, .. } = &frames[0] else {
        panic!("not crypto");
    };
    let offer = Hello::offered(data).unwrap();
    assert_eq!(offer.offer(), hello.offer());
    let spoken = spoken(&offer, &held, &chosen, [8u8; 32]).unwrap();
    let secret = Group::X25519.agree(&chosen, &share(&offer)).unwrap();
    let accepted = offer.accept(&spoken.reply, &secret).unwrap();
    let initial = space(Kind::Initial, &long.scid, &server);
    let start = initial
        .crypto(
            &Initial::new(&long.dcid).unwrap().server,
            0,
            &spoken.hello,
            0,
        )
        .unwrap();
    peer.send_to(&start, from).unwrap();
    let handshake = Handshake::new(
        Hash::Sha256,
        Aead::Aes128,
        accepted.client().secret(),
        accepted.server().secret(),
    )
    .unwrap();
    let flight = space(Kind::Handshake, &long.scid, &server);
    let rest = flight
        .crypto(&handshake.server, 0, &spoken.rest, 0)
        .unwrap();
    peer.send_to(&rest, from).unwrap();
    let (packet, _) = recv(&near);
    let mut hearing = Hearing::new(&original, client.len()).unwrap();
    hearing.ingest(&packet).unwrap();
    let accepted = hello
        .accept(&spoken.reply, &shared(&offered, &chosen))
        .unwrap();
    let mut handshake = Handshake::new(
        Hash::Sha256,
        Aead::Aes128,
        accepted.client().secret(),
        accepted.server().secret(),
    )
    .unwrap();
    let (packet, _) = recv(&near);
    handshake.ingest(&packet, client.len()).unwrap();
    let verified = accepted
        .checked(&held.host, &held.roots, held.now, handshake.crypto())
        .unwrap();
    let complete = verified.finish().unwrap();
    let back = space(Kind::Handshake, &server, &client);
    near.send(
        &back
            .crypto(&handshake.client, 1, complete.spoken(), 0)
            .unwrap(),
    )
    .unwrap();
    let (packet, _) = recv(&peer);
    let Header::Long(header) = Header::parse(&packet, server.len()).unwrap() else {
        panic!("not long");
    };
    let opened = handshake
        .client
        .unprotect(&packet, header.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { data, .. } = &frames[0] else {
        panic!("not crypto");
    };
    spoken.waiting.check(data).unwrap();
    peer.connect(from).unwrap();
    let applied = Applied::new(
        Hash::Sha256,
        Aead::Aes128,
        complete.client().secret(),
        complete.server().secret(),
    )
    .unwrap();
    Session {
        near,
        peer,
        applied,
        client: client.to_vec(),
        server: server.to_vec(),
    }
}

pub fn run() {
    let session = session();
    session
        .near
        .send(&protect(&session.applied.client, &session.server, b"ping"))
        .unwrap();
    let (packet, _) = recv(&session.peer);
    assert_eq!(
        open(&session.applied.client, &packet, session.server.len()),
        b"ping"
    );
    session
        .peer
        .send(&protect(&session.applied.server, &session.client, b"pong"))
        .unwrap();
    let (packet, _) = recv(&session.near);
    assert_eq!(
        open(&session.applied.server, &packet, session.client.len()),
        b"pong"
    );
}
