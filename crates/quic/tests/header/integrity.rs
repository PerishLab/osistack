use crate::support::*;
use crypto::{Aead, Error as Auth, Hash};
use quic::{Cycle, Error, Header, Keys, Kind, Long, Number, Opened, Quota, Retry, Short};

const ODCID: &str = "8394c8f03e515708";
const WIRE: &str = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
const TAG: &str = "04a265ba2eff4d829058fb3f0f2496ba";
const SCID: &str = "f067a5502a4262b5";

fn sample() -> Retry {
    Retry {
        unused: 0xf,
        dcid: Vec::new(),
        scid: hex(SCID),
        token: b"token".to_vec(),
        tag: [0; 16],
    }
}

fn known() -> Retry {
    let mut retry = sample();
    retry.tag = hex(TAG).try_into().unwrap();
    retry
}

#[test]
fn traces() {
    let retry = known();
    assert!(retry.check(&hex(ODCID)).is_ok());
    let mut filled = sample();
    filled.fill(&hex(ODCID)).unwrap();
    assert_eq!(filled.tag, retry.tag);
    assert_eq!(filled.write().unwrap(), hex(WIRE));
}

#[test]
fn filled() {
    let mut sender = sample();
    sender.fill(&hex(ODCID)).unwrap();
    let wire = sender.write().unwrap();
    let Header::Retry(receiver) = Header::parse(&wire, 0).unwrap() else {
        panic!();
    };
    assert!(receiver.check(&hex(ODCID)).is_ok());
}

#[test]
fn forged() {
    let odcid = hex(ODCID);
    let mut retry = known();
    retry.tag[0] ^= 1;
    assert_eq!(retry.check(&odcid), Err(Error::Crypto(Auth::Auth)));
    let mut token = known();
    token.token[0] ^= 1;
    assert_eq!(token.check(&odcid), Err(Error::Crypto(Auth::Auth)));
    let mut other = odcid.clone();
    other[0] ^= 1;
    assert_eq!(known().check(&other), Err(Error::Crypto(Auth::Auth)));
    assert_eq!(known().check(&[]), Err(Error::Crypto(Auth::Auth)));
}

#[test]
fn lengths() {
    let long = vec![1; 21];
    assert_eq!(sample().fill(&long), Err(Error::Length));
    assert_eq!(known().check(&long), Err(Error::Length));
    let mut empty = sample();
    empty.fill(&[]).unwrap();
    assert!(empty.check(&[]).is_ok());
    assert_eq!(empty.check(&hex(ODCID)), Err(Error::Crypto(Auth::Auth)));
    let mut max = sample();
    let ident = vec![7; 20];
    max.fill(&ident).unwrap();
    assert!(max.check(&ident).is_ok());
}

#[test]
fn caps() {
    assert_eq!(Quota::confidential(Aead::Aes128).cap(), 1 << 23);
    assert_eq!(Quota::confidential(Aead::Aes256).cap(), 1 << 23);
    assert_eq!(Quota::confidential(Aead::Chacha).cap(), 1 << 62);
    assert_eq!(Quota::integrity(Aead::Aes128).cap(), 1 << 52);
    assert_eq!(Quota::integrity(Aead::Aes256).cap(), 1 << 52);
    assert_eq!(Quota::integrity(Aead::Chacha).cap(), 1 << 36);
}

#[test]
fn consume() {
    for aead in [Aead::Aes128, Aead::Aes256, Aead::Chacha] {
        let mut quota = Quota::confidential(aead);
        quota.consume().unwrap();
        assert_eq!(quota.used(), 1);
        let cap = quota.cap();
        let mut last = Quota::confidential(aead).at(cap - 1);
        last.consume().unwrap();
        assert_eq!(last.used(), cap);
        assert_eq!(last.consume(), Err(Error::Limit));
        assert_eq!(last.used(), cap);
        let mut over = Quota::integrity(aead).at(Quota::integrity(aead).cap());
        assert_eq!(over.consume(), Err(Error::Limit));
        assert_eq!(
            Quota::confidential(aead).at(cap).consume(),
            Err(Error::Limit)
        );
    }
}

fn keys(aead: Aead) -> Keys {
    Keys::derive(Hash::Sha256, aead, &[7; 32]).unwrap()
}

fn pair(aead: Aead) -> (Cycle, Cycle) {
    let derived = keys(aead);
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

fn long(number: u64) -> (Vec<u8>, usize) {
    let coded = Number::new(number, None).unwrap();
    let header = Long {
        kind: Kind::Handshake,
        dcid: vec![4; 8],
        scid: vec![5; 4],
        token: Vec::new(),
        length: coded.length as u64 + 20,
        offset: 0,
    }
    .write(&coded)
    .unwrap();
    let offset = header.len() - coded.length;
    (header, offset)
}

fn opened(number: u64, header: &[u8], payload: &[u8]) -> Opened {
    Opened {
        number,
        header: header.to_vec(),
        payload: payload.to_vec(),
    }
}

#[test]
fn fresh() {
    for aead in [Aead::Aes128, Aead::Aes256, Aead::Chacha] {
        let (sender, receiver) = pair(aead);
        assert!(!sender.phase());
        let (header, offset) = short(false, 0);
        let packet = sender.protect(0, &header, b"ping").unwrap();
        assert_eq!(
            receiver.unprotect(&packet, offset, None).unwrap(),
            opened(0, &header, b"ping")
        );
        let (wrong, _) = short(true, 0);
        assert_eq!(sender.protect(0, &wrong, b"ping"), Err(Error::Kind));
    }
}

#[test]
fn advanced() {
    for aead in [Aead::Aes128, Aead::Aes256, Aead::Chacha] {
        let (mut sender, mut receiver) = pair(aead);
        sender.advance().unwrap();
        receiver.advance().unwrap();
        assert!(sender.phase());
        let (header, offset) = short(true, 1);
        let packet = sender.protect(1, &header, b"next").unwrap();
        assert_eq!(
            receiver.unprotect(&packet, offset, None).unwrap(),
            opened(1, &header, b"next")
        );
        let (header, offset) = long(2);
        let packet = sender.protect(2, &header, b"long").unwrap();
        assert_eq!(
            receiver.unprotect(&packet, offset, None).unwrap(),
            opened(2, &header, b"long")
        );
    }
}

#[test]
fn previous() {
    for aead in [Aead::Aes128, Aead::Aes256, Aead::Chacha] {
        let (sender, mut receiver) = pair(aead);
        let (header, offset) = short(false, 3);
        let packet = sender.protect(3, &header, b"old").unwrap();
        receiver.advance().unwrap();
        assert_eq!(
            receiver.unprotect(&packet, offset, None).unwrap(),
            opened(3, &header, b"old")
        );
        let (header, _) = short(false, 4);
        assert_eq!(receiver.protect(4, &header, b"send"), Err(Error::Kind));
    }
}

#[test]
fn mismatch() {
    for aead in [Aead::Aes128, Aead::Aes256, Aead::Chacha] {
        let (mut sender, receiver) = pair(aead);
        sender.advance().unwrap();
        let (header, offset) = short(true, 5);
        let packet = sender.protect(5, &header, b"new").unwrap();
        assert_eq!(
            receiver.unprotect(&packet, offset, None),
            Err(Error::Crypto(Auth::Auth))
        );
        let (header, offset) = long(6);
        let packet = sender.protect(6, &header, b"long").unwrap();
        assert!(receiver.unprotect(&packet, offset, None).is_err());
        assert_eq!(receiver.unprotect(&[], 1, None), Err(Error::Length));
        let (header, offset) = short(true, 7);
        let packet = keys(aead).protect(7, &header, b"sneak").unwrap();
        assert_eq!(
            receiver.unprotect(&packet, offset, None),
            Err(Error::Crypto(Auth::Auth))
        );
    }
}
