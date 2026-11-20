use crate::common::hex;
use crate::data::*;
use crypto::{Error, Hash, Scheme, Verifier};

const MESSAGE: &[u8] = b"sample";

fn good() -> Verifier {
    Verifier::ecdsa(&hex(POINT)).unwrap()
}

#[test]
fn rfc6979() {
    let signature = hex(SIGNATURE);
    assert_eq!(good().check(Scheme::Ecdsa, MESSAGE, &signature), Ok(()));
}

#[test]
fn flips() {
    let signature = hex(SIGNATURE);
    assert_eq!(
        good().check(Scheme::Ecdsa, b"other", &signature),
        Err(Error::Auth)
    );
    for at in 0..signature.len() {
        let mut flipped = signature.clone();
        flipped[at] ^= 1;
        let outcome = good().check(Scheme::Ecdsa, MESSAGE, &flipped);
        assert!(matches!(outcome, Err(Error::Auth | Error::Format)), "{at}");
    }
    let mut point = hex(POINT);
    point[40] ^= 1;
    let moved = Verifier::ecdsa(&point).unwrap();
    assert_eq!(
        moved.check(Scheme::Ecdsa, MESSAGE, &signature),
        Err(Error::Point)
    );
}

#[test]
fn malformed() {
    let signature = hex(SIGNATURE);
    let check = |bytes: &[u8]| good().check(Scheme::Ecdsa, MESSAGE, bytes);
    assert_eq!(check(&[]), Err(Error::Format));
    assert_eq!(check(&signature[..signature.len() - 1]), Err(Error::Format));
    assert_eq!(
        check(&[signature.clone(), vec![0]].concat()),
        Err(Error::Format)
    );
    assert_eq!(check(&[0x30, 0x00]), Err(Error::Format));
    assert_eq!(check(&[0u8; 64]), Err(Error::Format));
    assert_eq!(check(&[0x30, 0x06, 2, 1, 0, 2, 1, 0]), Err(Error::Auth));
}

#[test]
fn points() {
    for size in [0, 1, 33, 64, 66] {
        let made = Verifier::ecdsa(&vec![4; size]);
        assert_eq!(made.err(), Some(Error::Length), "{size}");
    }
    let mut compressed = hex(POINT);
    compressed[0] = 3;
    let bad = Verifier::ecdsa(&compressed).unwrap();
    assert_eq!(
        bad.check(Scheme::Ecdsa, MESSAGE, &hex(SIGNATURE)),
        Err(Error::Point)
    );
}

#[test]
fn schemes() {
    let signature = hex(SIGNATURE);
    for scheme in [
        Scheme::Pkcs1(Hash::Sha256),
        Scheme::Pss(Hash::Sha256),
        Scheme::Pkcs1(Hash::Sha384),
    ] {
        let outcome = good().check(scheme, MESSAGE, &signature);
        assert_eq!(outcome, Err(Error::Unsupported), "{scheme:?}");
    }
}
