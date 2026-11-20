use crate::common::hex;
use crate::data::*;
use crypto::{Error, Hash, Scheme, Verifier};

fn key() -> Verifier {
    Verifier::rsa(&hex(MODULUS), &hex(EXPONENT)).unwrap()
}

fn signatures() -> [(Scheme, Vec<u8>); 6] {
    [
        (Scheme::Pkcs1(Hash::Sha256), hex(PKCS256)),
        (Scheme::Pkcs1(Hash::Sha384), hex(PKCS384)),
        (Scheme::Pkcs1(Hash::Sha512), hex(PKCS512)),
        (Scheme::Pss(Hash::Sha256), hex(PSS256)),
        (Scheme::Pss(Hash::Sha384), hex(PSS384)),
        (Scheme::Pss(Hash::Sha512), hex(PSS512)),
    ]
}

#[test]
fn valid() {
    for (scheme, signature) in signatures() {
        assert_eq!(
            key().check(scheme, MESSAGE, &signature),
            Ok(()),
            "{scheme:?}"
        );
    }
}

#[test]
fn messages() {
    for (scheme, signature) in signatures() {
        let outcome = key().check(scheme, b"osistack seam!", &signature);
        assert_eq!(outcome, Err(Error::Auth), "{scheme:?}");
        assert_eq!(
            key().check(scheme, b"", &signature),
            Err(Error::Auth),
            "{scheme:?}"
        );
    }
}

#[test]
fn flips() {
    for (scheme, signature) in signatures() {
        for at in [0, 1, 100, 255] {
            let mut flipped = signature.clone();
            flipped[at] ^= 0x10;
            let outcome = key().check(scheme, MESSAGE, &flipped);
            assert_eq!(outcome, Err(Error::Auth), "{scheme:?} {at}");
        }
    }
}

#[test]
fn lengths() {
    for (scheme, signature) in signatures() {
        let check = |bytes: &[u8]| key().check(scheme, MESSAGE, bytes);
        assert_eq!(check(&signature[1..]), Err(Error::Auth), "{scheme:?}");
        assert_eq!(check(&signature[..255]), Err(Error::Auth), "{scheme:?}");
        let longer = [signature.clone(), vec![0]].concat();
        assert_eq!(check(&longer), Err(Error::Auth), "{scheme:?}");
        let leading = [vec![0], signature.clone()].concat();
        assert_eq!(check(&leading), Err(Error::Auth), "{scheme:?}");
        assert_eq!(check(&[]), Err(Error::Auth), "{scheme:?}");
        assert_eq!(check(&[0; 256]), Err(Error::Auth), "{scheme:?}");
        assert_eq!(check(&[0xff; 256]), Err(Error::Auth), "{scheme:?}");
    }
}

#[test]
fn crossed() {
    let all = signatures();
    for (scheme, _) in &all {
        for (other, signature) in &all {
            if scheme != other {
                let outcome = key().check(*scheme, MESSAGE, signature);
                assert_eq!(outcome, Err(Error::Auth), "{scheme:?} {other:?}");
            }
        }
    }
}

#[test]
fn moduli() {
    let wide = Scheme::Pss(Hash::Sha256);
    let signature = hex(PSS256);
    assert_eq!(key().check(wide, MESSAGE, &signature), Ok(()));
    let mut other = hex(MODULUS);
    other[255] ^= 2;
    let moved = Verifier::rsa(&other, &hex(EXPONENT)).unwrap();
    assert_eq!(moved.check(wide, MESSAGE, &signature), Err(Error::Auth));
}

#[test]
fn exponents() {
    let modulus = hex(MODULUS);
    let three = Verifier::rsa(&modulus, &[3]).unwrap();
    for (scheme, signature) in signatures() {
        let outcome = three.check(scheme, MESSAGE, &signature);
        assert_eq!(outcome, Err(Error::Auth), "{scheme:?}");
    }
}

#[test]
fn unsupported() {
    let signature = hex(PKCS256);
    assert_eq!(
        key().check(Scheme::Ecdsa, MESSAGE, &signature),
        Err(Error::Unsupported)
    );
}
