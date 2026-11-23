use http::Error;
use std::collections::HashSet;

const ALL: [Error; 12] = [
    Error::Empty,
    Error::Character,
    Error::Padding,
    Error::Range,
    Error::Scheme,
    Error::Userinfo,
    Error::Host,
    Error::Port,
    Error::Order,
    Error::Duplicate,
    Error::Pseudo,
    Error::Target,
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
    let boxed: Box<dyn std::error::Error> = Box::new(Error::Empty);
    assert_eq!(boxed.to_string(), Error::Empty.to_string());
}
