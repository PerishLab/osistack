use h1::Error;
use std::collections::HashSet;

const ALL: [Error; 14] = [
    Error::Size,
    Error::Line,
    Error::Version,
    Error::Status,
    Error::Space,
    Error::Fold,
    Error::Field,
    Error::Length,
    Error::Ambiguous,
    Error::Encoding,
    Error::Chunk,
    Error::Trailer,
    Error::Target,
    Error::Host,
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
    let boxed: Box<dyn std::error::Error> = Box::new(Error::Size);
    assert_eq!(boxed.to_string(), Error::Size.to_string());
}
