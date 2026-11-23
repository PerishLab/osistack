mod closing;
mod cycle;
mod flow;
mod path;
mod remote;
mod reset;
mod streams;

pub(crate) use remote::session;

use crate::tls::{mint, spoken};
use crypto::{Aead, Group, Hash};
use quic::{
    Applied, Flight, Frame, Handshake, Header, Hearing, Initial, Kind, Number, Opening, Param,
    Params, Short,
};
use tls::{Extension, Hello, Message, Share};

pub(super) fn params(scid: &[u8]) -> Params {
    Params {
        list: vec![Param::Idle(30_000), Param::Source(scid.to_vec())],
    }
}

pub(super) fn hello(secret: &[u8; 32], scid: &[u8]) -> Hello {
    let share = Share {
        group: 0x001d,
        key: Group::X25519.public(secret).unwrap(),
    };
    let base = Hello::start(b"example.test", &[b"h3".to_vec()], share, [7u8; 32]).unwrap();
    let mut offer = base.offer().clone();
    offer.extensions.push(Extension {
        kind: 0x39,
        data: params(scid).write().unwrap(),
    });
    let message = Message {
        kind: tls::Kind::Offer,
        body: offer.write().unwrap(),
    };
    Hello::offered(&message.write().unwrap()).unwrap()
}

pub(super) fn shared(offered: &[u8; 32], chosen: &[u8; 32]) -> Vec<u8> {
    Group::X25519
        .agree(offered, &Group::X25519.public(chosen).unwrap())
        .unwrap()
}

pub fn client() {
    remote::run();
}

#[test]
fn finishes() {
    let original = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = [9u8; 4];
    let server = [4u8; 8];
    let offered = [9u8; 32];
    let chosen = [8u8; 32];
    let hello = hello(&offered, &client);
    let _opening = Opening {
        dcid: original.to_vec(),
        scid: client.to_vec(),
        token: Vec::new(),
    }
    .write(hello.spoken())
    .unwrap();
    let held = mint("example.test");
    let spoken = spoken(&hello, &held, &chosen, [8u8; 32]).unwrap();
    let initial = Flight {
        kind: Kind::Initial,
        dcid: client.to_vec(),
        scid: server.to_vec(),
        token: Vec::new(),
    };
    let packet = initial
        .crypto(
            &Initial::new(&original).unwrap().server,
            0,
            &spoken.hello,
            0,
        )
        .unwrap();
    let mut hearing = Hearing::new(&original, client.len()).unwrap();
    hearing.ingest(&packet).unwrap();
    assert_eq!(hearing.crypto(), spoken.hello.as_slice());
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
    let space = Flight {
        kind: Kind::Handshake,
        dcid: client.to_vec(),
        scid: server.to_vec(),
        token: Vec::new(),
    };
    let packet = space.crypto(&handshake.server, 0, &spoken.rest, 0).unwrap();
    handshake.ingest(&packet, client.len()).unwrap();
    assert_eq!(handshake.crypto(), spoken.rest.as_slice());
    let verified = accepted
        .checked(&held.host, &held.roots, held.now, handshake.crypto())
        .unwrap();
    let complete = verified.finish().unwrap();
    spoken.waiting.check(complete.spoken()).unwrap();
    let packet = space
        .crypto(&handshake.client, 1, complete.spoken(), 0)
        .unwrap();
    let Header::Long(long) = Header::parse(&packet, server.len()).unwrap() else {
        panic!("not long");
    };
    let opened = handshake
        .client
        .unprotect(&packet, long.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { offset, data } = &frames[0] else {
        panic!("not crypto");
    };
    assert_eq!((*offset, data.as_slice()), (0, complete.spoken()));
    let applied = Applied::new(
        Hash::Sha256,
        Aead::Aes128,
        complete.client().secret(),
        complete.server().secret(),
    )
    .unwrap();
    let number = Number::new(0, None).unwrap();
    let short = Short {
        spin: false,
        phase: false,
        dcid: server.to_vec(),
        offset: 0,
    };
    let packet = applied
        .client
        .protect(0, &short.write(&number).unwrap(), b"app")
        .unwrap();
    let opened = applied
        .client
        .unprotect(&packet, 1 + server.len(), None)
        .unwrap();
    assert_eq!(opened.payload, b"app");
}
