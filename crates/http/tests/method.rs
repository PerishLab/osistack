use http::{Error, Method};

#[test]
fn tokens() {
    for text in ["GET", "POST", "M-SEARCH", "PATCH", "x.y_z~1"] {
        assert_eq!(Method::new(text).unwrap().text(), text);
    }
}

#[test]
fn sensitive() {
    assert_ne!(Method::new("get").unwrap(), Method::new("GET").unwrap());
}

#[test]
fn empty() {
    assert_eq!(Method::new(""), Err(Error::Empty));
}

#[test]
fn separators() {
    for text in [
        "GE T", "GET\r\n", "GET/1", "G:T", "(GET)", "GÉT", "GET\0", "a,b", "a;b",
    ] {
        assert_eq!(Method::new(text), Err(Error::Character), "{text:?}");
    }
}
