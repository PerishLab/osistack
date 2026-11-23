use h3::Error;
use std::collections::HashSet;
use std::error::Error as Std;

const ALL: [Error; 11] = [
    Error::Index,
    Error::Dynamic,
    Error::Count,
    Error::Base,
    Error::Capacity,
    Error::Oversize,
    Error::Zero,
    Error::Blocked,
    Error::Reference,
    Error::Pinned,
    Error::Feedback,
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
    assert!(Error::Index.source().is_none());
}
