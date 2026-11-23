use crate::data::*;
use crate::support::*;
use crypto::{Aead, Hash};
use tls::Error;

const AUTH: Error = Error::Crypto(crypto::Error::Auth);

#[test]
fn lengths() {
    let schedule = schedule(SHARED);
    let master = master(SHARED);
    let traffic = schedule.server(&hex(HELLOS)).unwrap();
    for size in [0, 1, 31, 33, 48, 64] {
        let wrong = vec![0u8; size];
        assert_eq!(schedule.client(&wrong).err(), Some(Error::Length), "{size}");
        assert_eq!(schedule.server(&wrong).err(), Some(Error::Length), "{size}");
        assert_eq!(master.client(&wrong).err(), Some(Error::Length), "{size}");
        assert_eq!(master.server(&wrong).err(), Some(Error::Length), "{size}");
        assert_eq!(master.exporter(&wrong).err(), Some(Error::Length), "{size}");
        assert_eq!(
            master.resumption(&wrong).err(),
            Some(Error::Length),
            "{size}"
        );
        assert_eq!(
            traffic.finished(&wrong).err(),
            Some(Error::Length),
            "{size}"
        );
        let tag = hex(SERVERFIN);
        assert_eq!(
            traffic.check(&wrong, &tag).err(),
            Some(Error::Length),
            "{size}"
        );
    }
}

#[test]
fn tampered() {
    let traffic = schedule(SHARED).server(&hex(HELLOS)).unwrap();
    let hash = hex(VERIFIED);
    let tag = hex(SERVERFIN);
    for at in 0..tag.len() {
        let mut bad = tag.clone();
        bad[at] ^= 1;
        assert_eq!(traffic.check(&hash, &bad).err(), Some(AUTH), "{at}");
    }
    for size in [0, 31, 33] {
        let wrong = vec![0u8; size];
        assert_eq!(traffic.check(&hash, &wrong).err(), Some(AUTH), "{size}");
    }
    assert_eq!(traffic.check(&hex(HELLOS), &tag).err(), Some(AUTH));
    let client = schedule(SHARED).client(&hex(HELLOS)).unwrap();
    assert_eq!(client.check(&hash, &tag).err(), Some(AUTH));
}

#[test]
fn wide() {
    let shared = hex(SHARED);
    let made = tls::Schedule::new(Hash::Sha384, &shared);
    assert!(made.is_ok());
    let wide = tls::Schedule::new(Hash::Sha512, &shared);
    assert!(wide.is_ok());
}

#[test]
fn distinct() {
    let base = schedule(SHARED).client(&hex(HELLOS)).unwrap();
    let mut flipped = hex(SHARED);
    flipped[0] ^= 1;
    let other = tls::Schedule::new(Hash::Sha256, &flipped).unwrap();
    assert_ne!(other.client(&hex(HELLOS)).unwrap().secret(), base.secret());
    let moved = schedule(SHARED).client(&hex(VERIFIED)).unwrap();
    assert_ne!(moved.secret(), base.secret());
    let client = schedule(SHARED).client(&hex(HELLOS)).unwrap();
    let server = schedule(SHARED).server(&hex(HELLOS)).unwrap();
    assert_ne!(client.secret(), server.secret());
}

#[test]
fn edges() {
    let empty = tls::Schedule::new(Hash::Sha256, &[]).unwrap();
    let zeros = tls::Schedule::new(Hash::Sha256, &[0; 32]).unwrap();
    let hash = hex(HELLOS);
    let first = empty.client(&hash).unwrap();
    let second = zeros.client(&hash).unwrap();
    assert_eq!(first.secret().len(), 32);
    assert_eq!(second.secret().len(), 32);
    assert_ne!(first.secret(), second.secret());
}

#[test]
fn copies() {
    let schedule = schedule(SHARED);
    let copy = schedule.clone();
    let hash = hex(HELLOS);
    let one = schedule.client(&hash).unwrap();
    let two = copy.client(&hash).unwrap();
    assert_eq!(one.secret(), two.secret());
    let kept = one.clone();
    let next = one.update().unwrap();
    assert_eq!(kept.secret(), two.secret());
    assert_ne!(next.secret(), kept.secret());
    let sizes = [(Aead::Aes128, 16), (Aead::Aes256, 32), (Aead::Chacha, 32)];
    for (aead, size) in sizes {
        let made = kept.keys(aead).unwrap();
        assert_eq!((made.key.len(), made.iv.len()), (size, 12), "{aead:?}");
    }
}
