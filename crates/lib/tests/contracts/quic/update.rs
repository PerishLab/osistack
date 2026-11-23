use crate::behaviour::Check;
use crypto::{Aead, Hash};
use quic::{Cycle, Keys, Number, Short};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("key-update", update as Check)]
}

fn keys(hash: Hash, aead: Aead) -> Keys {
    Keys::derive(hash, aead, &vec![7u8; hash.size()]).unwrap()
}

fn pair(hash: Hash, aead: Aead) -> (Cycle, Cycle) {
    let derived = keys(hash, aead);
    (Cycle::new(derived.clone()), Cycle::new(derived))
}

fn short(phase: bool, number: u64) -> (Vec<u8>, usize) {
    let coded = Number::new(number, None).unwrap();
    let header = Short {
        spin: false,
        phase,
        dcid: vec![4; 8],
        offset: 0,
    }
    .write(&coded)
    .unwrap();
    (header, 9)
}

fn sealed(cycle: &Cycle, phase: bool, number: u64, text: &[u8]) -> (Vec<u8>, usize) {
    let (header, offset) = short(phase, number);
    let packet = cycle.protect(number, &header, text).unwrap();
    (packet, offset)
}

fn update() {
    for (hash, aead) in [
        (Hash::Sha256, Aead::Aes128),
        (Hash::Sha256, Aead::Chacha),
        (Hash::Sha384, Aead::Aes256),
    ] {
        rotate(hash, aead);
    }
}

fn rotate(hash: Hash, aead: Aead) {
    let (mut sender, mut receiver) = pair(hash, aead);
    assert!(!sender.phase());
    assert!(!receiver.phase());
    let (early, offset) = sealed(&sender, false, 0, b"before");
    let opened = receiver.unprotect(&early, offset, None).unwrap();
    assert_eq!((opened.number, opened.payload), (0, b"before".to_vec()));
    sender.advance().unwrap();
    receiver.advance().unwrap();
    assert!(sender.phase());
    assert!(receiver.phase());
    let (fresh, offset) = sealed(&sender, true, 1, b"after");
    let opened = receiver.unprotect(&fresh, offset, None).unwrap();
    assert_eq!((opened.number, opened.payload), (1, b"after".to_vec()));
    assert!(keys(hash, aead).unprotect(&fresh, offset, None).is_err());
    assert!(receiver.unprotect(&early, 9, None).is_ok());
    let (header, _) = short(false, 2);
    assert!(sender.protect(2, &header, b"wrong").is_err());
    sender.advance().unwrap();
    receiver.advance().unwrap();
    assert!(!sender.phase());
    assert!(receiver.unprotect(&fresh, offset, None).is_ok());
    assert!(receiver.unprotect(&early, 9, None).is_err());
}
