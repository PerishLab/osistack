use h2::Error;
use std::collections::HashSet;
use std::error::Error as Std;

const ALL: [Error; 9] = [
    Error::Index,
    Error::Size,
    Error::Length,
    Error::Stream,
    Error::Padding,
    Error::Setting,
    Error::Increment,
    Error::Push,
    Error::Kind,
];

#[test]
fn texts() {
    let mut seen = HashSet::new();
    for error in ALL {
        let text = error.to_string();
        assert!(!text.is_empty(), "{error:?}");
        assert!(seen.insert(text), "{error:?}");
    }
    let wrapped = Error::Wire(wire::Error::Truncated);
    let text = wrapped.to_string();
    assert!(text.contains(&wire::Error::Truncated.to_string()));
    assert!(seen.insert(text));
}

#[test]
fn source() {
    let wrapped = Error::Wire(wire::Error::Range);
    assert_eq!(
        wrapped.source().map(ToString::to_string),
        Some(wire::Error::Range.to_string())
    );
    assert!(Error::Kind.source().is_none());
}
