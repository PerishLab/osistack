use crypto::{Aead, Group, Hash};
use quic::{Frame, Handshake, Hearing, Initial, Kind, Long, Number, Opening, Param, Params};
use tls::{Extension, Hello, Message, Place, Reply, Share, Typed};

struct Dest {
    kind: Kind,
    dcid: Vec<u8>,
    scid: Vec<u8>,
}

impl Dest {
    fn packet(&self, keys: &quic::Keys, number: u64, payload: &[u8]) -> Vec<u8> {
        let written = Number::new(number, None).unwrap();
        let long = Long {
            kind: self.kind,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            token: Vec::new(),
            length: (written.length + payload.len() + 16) as u64,
            offset: 0,
        };
        keys.protect(number, &long.write(&written).unwrap(), payload)
            .unwrap()
    }

    fn crypto(&self, keys: &quic::Keys, number: u64, data: &[u8], offset: u64) -> Vec<u8> {
        let payload = Frame::Crypto {
            offset,
            data: data.to_vec(),
        }
        .write()
        .unwrap();
        self.packet(keys, number, &payload)
    }
}

fn params(scid: &[u8]) -> Params {
    Params {
        list: vec![Param::Idle(30_000), Param::Source(scid.to_vec())],
    }
}

fn hello(secret: &[u8; 32], scid: &[u8]) -> Hello {
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

fn reply(hello: &Hello, secret: &[u8; 32]) -> (Reply, Vec<u8>, Vec<u8>) {
    let mut found = None;
    for item in &hello.offer().extensions {
        if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer).unwrap() {
            found = items.into_iter().next();
        }
    }
    let taken = found.unwrap();
    let key = Group::X25519.public(secret).unwrap();
    let shared = Group::X25519.agree(secret, &taken.key).unwrap();
    let reply = Reply {
        random: [8u8; 32],
        session: hello.offer().session.clone(),
        suite: 0x1301,
        extensions: vec![
            Typed::Chosen(Share {
                group: taken.group,
                key,
            })
            .write()
            .unwrap(),
            Typed::Version(0x0304).write().unwrap(),
        ],
    };
    let spoken = Message {
        kind: tls::Kind::Reply,
        body: reply.write().unwrap(),
    }
    .write()
    .unwrap();
    (reply, spoken, shared)
}

fn retry() -> [u8; 32] {
    [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]
}

#[test]
fn accepts() {
    let original = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = [9u8; 4];
    let server = [4u8; 8];
    let offered = [9u8; 32];
    let chosen = [8u8; 32];
    let hello = hello(&offered, &client);
    let _packet = Opening {
        dcid: original.to_vec(),
        scid: client.to_vec(),
        token: Vec::new(),
    }
    .write(hello.spoken())
    .unwrap();
    let (reply, spoken, shared) = reply(&hello, &chosen);
    let initial = Dest {
        kind: Kind::Initial,
        dcid: client.to_vec(),
        scid: server.to_vec(),
    };
    let packet = initial.crypto(&Initial::new(&original).unwrap().server, 0, &spoken, 0);
    let mut hearing = Hearing::new(&original, client.len()).unwrap();
    assert_eq!(hearing.ingest(&packet).unwrap(), 0);
    assert_eq!(hearing.crypto(), spoken.as_slice());
    let accepted = hello.accept(&reply, &shared).unwrap();
    let mut handshake = Handshake::new(
        Hash::Sha256,
        Aead::Aes128,
        accepted.client().secret(),
        accepted.server().secret(),
    )
    .unwrap();
    let rest = b"more-handshake-crypto";
    let space = Dest {
        kind: Kind::Handshake,
        dcid: client.to_vec(),
        scid: server.to_vec(),
    };
    let first = space.crypto(&handshake.server, 0, &rest[..8], 0);
    let second = space.crypto(&handshake.server, 1, &rest[8..], 8);
    assert_eq!(handshake.ingest(&second, client.len()).unwrap(), 1);
    assert!(handshake.crypto().is_empty());
    assert_eq!(handshake.ingest(&first, client.len()).unwrap(), 0);
    assert_eq!(handshake.crypto(), rest);
}

#[test]
fn retries() {
    let original = [1u8; 8];
    let client = [2u8; 4];
    let server = [3u8; 8];
    let hello = hello(&[9u8; 32], &client);
    let reply = Reply {
        random: retry(),
        session: hello.offer().session.clone(),
        suite: 0x1301,
        extensions: vec![
            Typed::Group(0x001d).write().unwrap(),
            Typed::Version(0x0304).write().unwrap(),
            Typed::Cookie(b"token".to_vec()).write().unwrap(),
        ],
    };
    let spoken = Message {
        kind: tls::Kind::Reply,
        body: reply.write().unwrap(),
    }
    .write()
    .unwrap();
    let initial = Dest {
        kind: Kind::Initial,
        dcid: client.to_vec(),
        scid: server.to_vec(),
    };
    let packet = initial.crypto(&Initial::new(&original).unwrap().server, 0, &spoken, 0);
    let mut hearing = Hearing::new(&original, client.len()).unwrap();
    hearing.ingest(&packet).unwrap();
    assert_eq!(hearing.crypto(), spoken.as_slice());
    assert!(reply.retry());
    let share = Share {
        group: 0x001d,
        key: Group::X25519.public(&[5u8; 32]).unwrap(),
    };
    assert!(hello.retry(&reply, share).is_ok());
}

#[test]
fn refused() {
    let mut hearing = Hearing::new(&[1u8; 8], 4).unwrap();
    assert!(hearing.ingest(&[0u8; 8]).is_err());
    assert!(Handshake::new(Hash::Sha256, Aead::Aes128, &[], &[8u8; 32]).is_err());
}
