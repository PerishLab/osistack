use crypto::{Aead, Error, Group, Hash, Scheme, Verifier, hmac};
use std::collections::HashSet;

const ALL: [Error; 8] = [
    Error::Unsupported,
    Error::Length,
    Error::Auth,
    Error::Zero,
    Error::Point,
    Error::Scalar,
    Error::Format,
    Error::Key,
];

#[test]
fn texts() {
    let mut seen = HashSet::new();
    for error in ALL {
        let text = error.to_string();
        assert!(!text.is_empty(), "{error:?}");
        assert!(seen.insert(text), "{error:?}");
    }
}

#[test]
fn source() {
    let boxed: Box<dyn std::error::Error> = Box::new(Error::Auth);
    assert_eq!(boxed.to_string(), Error::Auth.to_string());
}

#[test]
fn mapped() {
    let point = vec![4u8; 65];
    let outcomes = [
        (
            Error::Unsupported,
            Verifier::ecdsa(&point)
                .unwrap()
                .check(Scheme::Pkcs1(Hash::Sha256), b"m", &[])
                .err(),
        ),
        (Error::Length, Aead::Aes128.cipher(&[0; 3]).err()),
        (
            Error::Auth,
            hmac::verify(Hash::Sha256, b"k", b"d", &[0; 32]).err(),
        ),
        (Error::Zero, Group::X25519.agree(&[5; 32], &[0; 32]).err()),
        (Error::Point, Group::Secp256r1.agree(&[5; 32], &point).err()),
        (Error::Scalar, Group::Secp256r1.public(&[0; 32]).err()),
        (
            Error::Format,
            Verifier::ecdsa(&point)
                .unwrap()
                .check(crypto::Scheme::Ecdsa, b"m", &[])
                .err(),
        ),
        (Error::Key, Verifier::rsa(&[0xff; 100], &[1, 0, 1]).err()),
    ];
    for (wanted, got) in outcomes {
        assert_eq!(got, Some(wanted));
    }
}
