use crate::behaviour::Check;
use crypto::{Aead, Group, Hash};
use tls::{Error, Master, Schedule, Traffic};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("key-schedule", keys as Check)]
}

struct End {
    hash: Hash,
    schedule: Schedule,
    sending: Traffic,
    receiving: Traffic,
}

fn nonce(iv: &[u8], number: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(iv);
    for (slot, byte) in out[4..].iter_mut().zip(number.to_be_bytes()) {
        *slot ^= byte;
    }
    out
}

fn send(aead: Aead, from: &Traffic, to: &Traffic, text: &[u8]) -> Result<Vec<u8>, Error> {
    let made = from.keys(aead)?;
    let cipher = aead.cipher(&made.key).unwrap();
    let mut data = text.to_vec();
    let tag = cipher
        .seal(&nonce(&made.iv, 7), b"record", &mut data)
        .unwrap();
    let theirs = to.keys(aead)?;
    let opener = aead.cipher(&theirs.key).unwrap();
    let opened = opener.open(&nonce(&theirs.iv, 7), b"record", &mut data, &tag);
    Ok(opened.map(|_| data).unwrap_or_default())
}

fn start(group: Group, own: u8, peer: u8) -> (Vec<u8>, Vec<u8>) {
    let mine = group.public(&[own; 32]).unwrap();
    let theirs = group.public(&[peer; 32]).unwrap();
    (mine, group.agree(&[own; 32], &theirs).unwrap())
}

fn begin(hash: Hash, shared: &[u8], mine: bool) -> End {
    let schedule = Schedule::new(hash, shared).unwrap();
    let hellos = hash.digest(b"client hello then server hello");
    let client = schedule.client(&hellos).unwrap();
    let server = schedule.server(&hellos).unwrap();
    let (sending, receiving) = if mine {
        (client, server)
    } else {
        (server, client)
    };
    End {
        hash,
        schedule,
        sending,
        receiving,
    }
}

fn finish(left: &End, right: &End) {
    let transcript = left.hash.digest(b"through certificate verify");
    let tag = left.sending.finished(&transcript).unwrap();
    assert_eq!(right.receiving.check(&transcript, &tag), Ok(()));
    let mut flipped = tag.clone();
    flipped[0] ^= 1;
    assert!(right.receiving.check(&transcript, &flipped).is_err());
    let later = left.hash.digest(b"through server finished");
    let reply = right.sending.finished(&later).unwrap();
    assert_eq!(left.receiving.check(&later, &reply), Ok(()));
}

fn apply(left: &End, right: &End) -> (Master, Master) {
    (
        left.schedule.master().unwrap(),
        right.schedule.master().unwrap(),
    )
}

fn keys() {
    for group in [Group::X25519, Group::Secp256r1] {
        let (first, shared) = start(group, 1, 2);
        let (second, other) = start(group, 2, 1);
        assert_ne!(first, second);
        assert_eq!(shared, other);
        for hash in [Hash::Sha256, Hash::Sha384] {
            let left = begin(hash, &shared, true);
            let right = begin(hash, &other, false);
            let aeads = if hash == Hash::Sha256 {
                [Aead::Aes128, Aead::Aes256, Aead::Chacha].as_slice()
            } else {
                [Aead::Aes256].as_slice()
            };
            for aead in aeads {
                let ping = send(*aead, &left.sending, &right.receiving, b"ping");
                assert_eq!(ping.unwrap(), b"ping", "{group:?} {hash:?} {aead:?}");
                let pong = send(*aead, &right.sending, &left.receiving, b"pong");
                assert_eq!(pong.unwrap(), b"pong", "{group:?} {hash:?} {aead:?}");
            }
            finish(&left, &right);
            rotate(&left, &right);
        }
    }
}

fn rotate(left: &End, right: &End) {
    let (one, two) = apply(left, right);
    let done = left.hash.digest(b"through server finished");
    let sent = one.client(&done).unwrap();
    let got = two.client(&done).unwrap();
    let aead = if left.hash == Hash::Sha384 {
        Aead::Aes256
    } else {
        Aead::Aes128
    };
    assert_eq!(send(aead, &sent, &got, b"early").unwrap(), b"early");
    let next = sent.update().unwrap();
    assert!(send(aead, &next, &got, b"late").unwrap().is_empty());
    let moved = got.update().unwrap();
    assert_eq!(send(aead, &next, &moved, b"late").unwrap(), b"late");
    assert_eq!(one.exporter(&done).unwrap(), two.exporter(&done).unwrap());
    assert_ne!(one.exporter(&done).unwrap(), one.resumption(&done).unwrap());
}
