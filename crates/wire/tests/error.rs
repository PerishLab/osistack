use std::collections::HashSet;
use wire::Error;

const ALL: [Error; 4] = [
    Error::Truncated,
    Error::Range,
    Error::Symbol,
    Error::Padding,
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
    let boxed: Box<dyn std::error::Error> = Box::new(Error::Truncated);
    assert_eq!(boxed.to_string(), Error::Truncated.to_string());
}
