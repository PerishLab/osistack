use crate::behaviour::Check;
use crypto::{Aead, Group, Hash};
use tls::{Content, Error, Layer, Opened, Schedule};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("record-protection", records as Check),
        ("aes-gcm", aes as Check),
        ("chacha20-poly1305", chacha as Check),
    ]
}

fn start(group: Group, own: u8, peer: u8) -> Vec<u8> {
    let theirs = group.public(&[peer; 32]).unwrap();
    group.agree(&[own; 32], &theirs).unwrap()
}

fn hellos(hash: Hash) -> Vec<u8> {
    hash.digest(b"client hello then server hello")
}

fn layer(hash: Hash, shared: &[u8], mine: bool, aead: Aead) -> Layer {
    let schedule = Schedule::new(hash, shared).unwrap();
    let traffic = if mine {
        schedule.client(&hellos(hash)).unwrap()
    } else {
        schedule.server(&hellos(hash)).unwrap()
    };
    Layer::new(aead, &traffic.keys(aead).unwrap()).unwrap()
}

struct Case {
    content: Content,
    data: &'static [u8],
    pad: usize,
}

fn trip(hash: Hash, aead: Aead, shared: &[u8], case: Case) {
    let mut sender = layer(hash, shared, true, aead);
    let mut receiver = layer(hash, shared, true, aead);
    let record = sender.protect(case.content, case.data, case.pad).unwrap();
    assert_eq!(record.content, Content::Application);
    assert_eq!(
        receiver.unprotect(&record).unwrap(),
        Opened {
            content: case.content,
            payload: case.data.to_vec(),
        }
    );
    let mut flipped = record.clone();
    flipped.fragment[0] ^= 1;
    assert!(receiver.unprotect(&flipped).is_err());
    let again = sender.protect(case.content, case.data, case.pad).unwrap();
    assert_ne!(again.fragment, record.fragment);
    assert_eq!(receiver.unprotect(&again).unwrap().payload, case.data);
}

fn records() {
    let shared = start(Group::X25519, 1, 2);
    let other = start(Group::X25519, 2, 1);
    assert_eq!(shared, other);
    for (hash, aead) in [
        (Hash::Sha256, Aead::Aes128),
        (Hash::Sha256, Aead::Aes256),
        (Hash::Sha256, Aead::Chacha),
        (Hash::Sha384, Aead::Aes256),
    ] {
        trip(
            hash,
            aead,
            &shared,
            Case {
                content: Content::Application,
                data: b"ping",
                pad: 0,
            },
        );
        trip(
            hash,
            aead,
            &shared,
            Case {
                content: Content::Handshake,
                data: b"finished-message",
                pad: 7,
            },
        );
        trip(
            hash,
            aead,
            &shared,
            Case {
                content: Content::Alert,
                data: b"\x01\x00",
                pad: 0,
            },
        );
        let mut sender = layer(hash, &shared, true, aead);
        assert_eq!(sender.protect(Content::Handshake, b"", 0), Err(Error::Kind));
    }
}

fn suite(pairs: &[(Hash, Aead)]) {
    let shared = start(Group::X25519, 1, 2);
    for &(hash, aead) in pairs {
        trip(
            hash,
            aead,
            &shared,
            Case {
                content: Content::Application,
                data: b"ping",
                pad: 0,
            },
        );
        trip(
            hash,
            aead,
            &shared,
            Case {
                content: Content::Handshake,
                data: b"finished-message",
                pad: 7,
            },
        );
        let mut sender = layer(hash, &shared, true, aead);
        assert_eq!(sender.protect(Content::Handshake, b"", 0), Err(Error::Kind));
    }
}

fn aes() {
    suite(&[
        (Hash::Sha256, Aead::Aes128),
        (Hash::Sha256, Aead::Aes256),
        (Hash::Sha384, Aead::Aes256),
    ]);
}

fn chacha() {
    suite(&[(Hash::Sha256, Aead::Chacha)]);
}
