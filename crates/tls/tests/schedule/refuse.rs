use crate::data::*;
use crate::support::hex;
use crypto::Aead;
use tls::{Content, Error, Keys, Layer, Record};

fn keys(key: &str, iv: &str) -> Keys {
    Keys {
        key: hex(key),
        iv: hex(iv),
    }
}

fn fresh() -> Layer {
    Layer::new(Aead::Aes128, &keys(CAPKEY, CAPIV)).unwrap()
}

fn sample() -> Record {
    fresh().protect(Content::Application, b"data", 0).unwrap()
}

#[test]
fn lengths() {
    let mut layer = fresh();
    let over = vec![0u8; 16385];
    assert_eq!(
        layer.protect(Content::Application, &over, 0),
        Err(Error::Length)
    );
    assert_eq!(
        layer.protect(Content::Application, &[0; 10], usize::MAX),
        Err(Error::Length)
    );
    let pad = 16640 - 16 - 10 - 1 + 1;
    assert_eq!(
        layer.protect(Content::Application, &[0; 10], pad),
        Err(Error::Length)
    );
    let ok = 16640 - 16 - 10 - 1;
    assert!(layer.protect(Content::Application, &[0; 10], ok).is_ok());
    let mut room = fresh();
    assert!(
        room.protect(Content::Application, &vec![0u8; 16384], 0)
            .is_ok()
    );
}

#[test]
fn empty() {
    let mut layer = fresh();
    assert_eq!(layer.protect(Content::Handshake, b"", 0), Err(Error::Kind));
    assert_eq!(layer.protect(Content::Alert, b"", 4), Err(Error::Kind));
    assert_eq!(layer.protect(Content::Change, b"x", 0), Err(Error::Kind));
    let record = layer.protect(Content::Application, b"", 0).unwrap();
    let mut other = fresh();
    let opened = other.unprotect(&record).unwrap();
    assert_eq!(opened.content, Content::Application);
    assert!(opened.payload.is_empty());
}

#[test]
fn held() {
    let mut layer = fresh();
    let good = layer.protect(Content::Application, b"one", 0).unwrap();
    let next = layer.protect(Content::Application, b"two", 0).unwrap();
    let mut other = fresh();
    let mut bad = good.clone();
    bad.fragment[0] ^= 1;
    assert!(other.unprotect(&bad).is_err());
    assert_eq!(other.unprotect(&good).unwrap().payload, b"one");
    let mut short = next.clone();
    short.fragment.truncate(16);
    assert_eq!(other.unprotect(&short), Err(Error::Length));
    assert_eq!(other.unprotect(&next).unwrap().payload, b"two");
}

#[test]
fn header() {
    let mut layer = fresh();
    let good = sample();
    let mut kind = good.clone();
    kind.content = Content::Handshake;
    assert_eq!(layer.unprotect(&kind), Err(Error::Kind));
    let mut version = good.clone();
    version.version = 0x0301;
    assert!(layer.unprotect(&version).is_err());
    assert_eq!(layer.unprotect(&good).unwrap().payload, b"data");
}

#[test]
fn forged() {
    let mut layer = fresh();
    let good = sample();
    for at in 0..good.fragment.len() {
        let mut bad = good.clone();
        bad.fragment[at] ^= 1;
        assert!(layer.unprotect(&bad).is_err(), "byte {at}");
    }
    assert_eq!(layer.unprotect(&good).unwrap().payload, b"data");
}

#[test]
fn wrapping() {
    let mut layer = Layer::at(Aead::Aes128, &keys(CAPKEY, CAPIV), u64::MAX).unwrap();
    assert_eq!(
        layer.protect(Content::Application, b"end", 0),
        Err(Error::Length)
    );
    let record = sample();
    assert_eq!(layer.unprotect(&record), Err(Error::Length));
}

#[test]
fn shape() {
    assert!(Layer::new(Aead::Aes128, &keys(CAPKEY, "00")).is_err());
    assert!(Layer::new(Aead::Aes256, &keys(CAPKEY, CAPIV)).is_err());
    assert!(Layer::new(Aead::Chacha, &keys(CAPKEY, CAPIV)).is_err());
    let wide = Keys {
        key: vec![7; 32],
        iv: hex(CAPIV),
    };
    assert!(Layer::new(Aead::Aes256, &wide).is_ok());
    assert!(Layer::new(Aead::Chacha, &wide).is_ok());
}

#[test]
fn padded() {
    let mut layer = fresh();
    let record = layer.protect(Content::Handshake, b"abc", 3).unwrap();
    assert_eq!(record.fragment.len(), 3 + 1 + 3 + 16);
    let mut other = fresh();
    let opened = other.unprotect(&record).unwrap();
    assert_eq!(opened.content, Content::Handshake);
    assert_eq!(opened.payload, b"abc");
}

fn planted(content: u8, data: &[u8]) -> Record {
    let made = keys(CAPKEY, CAPIV);
    let mut inner = data.to_vec();
    inner.push(content);
    let mut aad = [23, 0x03, 0x03, 0, 0];
    let length = u16::try_from(inner.len() + 16).unwrap();
    aad[3..].copy_from_slice(&length.to_be_bytes());
    let nonce: [u8; 12] = made.iv.as_slice().try_into().unwrap();
    let tag = Aead::Aes128
        .cipher(&made.key)
        .unwrap()
        .seal(&nonce, &aad, &mut inner)
        .unwrap();
    inner.extend_from_slice(&tag);
    Record {
        content: Content::Application,
        version: 0x0303,
        fragment: inner,
    }
}

#[test]
fn inner() {
    let mut layer = fresh();
    assert_eq!(layer.unprotect(&planted(22, b"")), Err(Error::Kind));
    assert_eq!(layer.unprotect(&planted(21, b"")), Err(Error::Kind));
    assert_eq!(layer.unprotect(&planted(20, b"x")), Err(Error::Kind));
    assert_eq!(
        layer.unprotect(&planted(22, b"ok")).unwrap().content,
        Content::Handshake
    );
}
