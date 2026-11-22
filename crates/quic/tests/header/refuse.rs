use crate::seeds::*;
use crate::support::*;
use crypto::{Aead, Hash};
use quic::{Error, Initial, Keys};

const DCID: &str = "8394c8f03e515708";
const CLIENTHEAD: &str = "c300000001088394c8f03e5157080000449e00000002";

const UNSUPPORTED: Error = Error::Crypto(crypto::Error::Unsupported);
const AUTH: Error = Error::Crypto(crypto::Error::Auth);

fn client() -> Keys {
    Initial::new(&hex(DCID)).unwrap().client
}

fn packet() -> Vec<u8> {
    let keys = Initial::new(&hex(DCID)).unwrap().server;
    let header = hex("c1000000010008f067a5502a4262b50040750001");
    keys.protect(1, &header, &hex(SERVERPAYLOAD)).unwrap()
}

#[test]
fn derive() {
    let ok = hex(DCID);
    assert!(Initial::new(&[0; 20]).is_ok());
    assert!(Initial::new(&[]).is_ok());
    assert_eq!(Initial::new(&[0; 21]).err(), Some(Error::Length));
    assert!(Initial::new(&ok).is_ok());
    for aead in [Aead::Aes256, Aead::Chacha] {
        let made = Keys::derive(Hash::Sha384, aead, &[7; 48]);
        assert!(made.is_ok(), "{aead:?}");
    }
    assert_eq!(
        Keys::derive(Hash::Sha512, Aead::Aes128, &[7; 64]).err(),
        Some(UNSUPPORTED)
    );
    let short = Keys::derive(Hash::Sha256, Aead::Aes128, &[7; 31]);
    assert!(matches!(short.err(), Some(Error::Crypto(_))));
}

#[test]
fn protect() {
    let keys = client();
    let head = hex(CLIENTHEAD);
    assert_eq!(keys.protect(2, &[], b"x").err(), Some(Error::Length));
    assert_eq!(
        keys.protect(2, &[3, 0, 0, 2], b"x").err(),
        Some(Error::Length)
    );
    assert_eq!(keys.protect(3, &head, b"x").err(), Some(Error::Number));
    let zero = hex("c300000001088394c8f03e5157080000449e00000000");
    assert_eq!(
        keys.protect(1 << 62, &zero, b"x").err(),
        Some(Error::Number)
    );
    assert!(
        keys.protect(
            (1 << 62) - 1,
            &hex("c300000001088394c8f03e5157080000449effffffff"),
            b"x"
        )
        .is_ok()
    );
    let top = (1u64 << 62) + 2;
    assert_eq!(keys.protect(top, &head, b"x").err(), Some(Error::Number));
    let short = hex("4200bff4");
    let low = Keys::derive(Hash::Sha256, Aead::Chacha, &[9; 32]).unwrap();
    assert_eq!(low.protect(0xbff4, &short, &[]).err(), Some(Error::Length));
    assert!(low.protect(0xbff4, &short, &[1]).is_ok());
}

#[test]
fn truncated() {
    let keys = Initial::new(&hex(DCID)).unwrap().server;
    let whole = packet();
    for size in [0, 1, 18, 37] {
        let cut = &whole[..size.min(whole.len())];
        assert_eq!(
            keys.unprotect(cut, 18, None).err(),
            Some(Error::Length),
            "{size}"
        );
    }
    let edge = keys.unprotect(&whole[..38], 18, None);
    assert_eq!(edge.err(), Some(AUTH));
    assert_eq!(keys.unprotect(&whole, 0, None).err(), Some(Error::Length));
    assert_eq!(keys.unprotect(&whole, 200, None).err(), Some(Error::Length));
    assert_eq!(
        keys.unprotect(&whole, usize::MAX, None).err(),
        Some(Error::Length)
    );
    assert!(keys.unprotect(&whole, 18, None).is_ok());
}

#[test]
fn tampered() {
    let keys = Initial::new(&hex(DCID)).unwrap().server;
    let whole = packet();
    for at in 0..whole.len() {
        let mut bad = whole.clone();
        bad[at] ^= 1;
        assert!(keys.unprotect(&bad, 18, None).is_err(), "{at}");
    }
    for at in 6..18 {
        let mut bad = whole.clone();
        bad[at] ^= 0x80;
        assert_eq!(keys.unprotect(&bad, 18, None).err(), Some(AUTH), "{at}");
    }
    let body = whole.len() - 1;
    let mut bad = whole.clone();
    bad[body] ^= 0x80;
    assert_eq!(keys.unprotect(&bad, 18, None).err(), Some(AUTH));
}

#[test]
fn reserved() {
    let keys = Initial::new(&hex(DCID)).unwrap().server;
    let mut bad = packet();
    bad[0] ^= 0x08;
    assert_eq!(keys.unprotect(&bad, 18, None).err(), Some(Error::Reserved));
    let mut short = Keys::derive(Hash::Sha256, Aead::Chacha, &[9; 32]).unwrap();
    short = short.update().unwrap();
    let mut made = short
        .protect(5, &[0x41, 0x00, 0x05], &[1, 2, 3, 4])
        .unwrap();
    made[0] ^= 0x10;
    assert_eq!(short.unprotect(&made, 1, None).err(), Some(Error::Reserved));
}

#[test]
fn crossed() {
    let initial = Initial::new(&hex(DCID)).unwrap();
    let other = Initial::new(&hex("8394c8f03e515709")).unwrap();
    let whole = packet();
    for keys in [&initial.client, &other.server] {
        let failed = keys.unprotect(&whole, 18, None).err();
        assert!(
            matches!(failed, Some(Error::Reserved) | Some(AUTH)),
            "{failed:?}"
        );
    }
    assert!(initial.server.unprotect(&whole, 18, None).is_ok());
    let next = initial.server.update().unwrap();
    assert!(next.unprotect(&whole, 18, None).is_err());
}

#[test]
fn numbers() {
    let initial = Initial::new(&hex(DCID)).unwrap();
    let whole = packet();
    let opened = initial.server.unprotect(&whole, 18, Some(0)).unwrap();
    assert_eq!(opened.number, 1);
    let far = initial.server.unprotect(&whole, 18, Some(1 << 40));
    assert!(far.is_err());
}
