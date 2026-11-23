use std::collections::HashSet;
use std::error::Error as Std;
use tls::Error;

const ALL: [Error; 10] = [
    Error::Kind,
    Error::Length,
    Error::Version,
    Error::Suites,
    Error::Compression,
    Error::Duplicate,
    Error::Trailing,
    Error::Value,
    Error::Missing,
    Error::Place,
];

#[test]
fn texts() {
    let mut seen = HashSet::new();
    for error in ALL {
        let text = error.to_string();
        assert!(!text.is_empty(), "{error:?}");
        assert!(seen.insert(text), "{error:?}");
    }
    let wire = Error::Wire(wire::Error::Truncated);
    let crypto = Error::Crypto(crypto::Error::Auth);
    assert!(
        wire.to_string()
            .contains(&wire::Error::Truncated.to_string())
    );
    assert!(
        crypto
            .to_string()
            .contains(&crypto::Error::Auth.to_string())
    );
    assert!(seen.insert(wire.to_string()));
    assert!(seen.insert(crypto.to_string()));
}

#[test]
fn source() {
    let wrapped = Error::Crypto(crypto::Error::Auth);
    assert_eq!(
        wrapped.source().map(ToString::to_string),
        Some(crypto::Error::Auth.to_string())
    );
    assert!(Error::Kind.source().is_none());
}
