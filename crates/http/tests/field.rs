use http::{Error, Name, Value};

#[test]
fn lowercase() {
    let name = Name::new("Content-Length").unwrap();
    assert_eq!(name.text(), "content-length");
    assert_eq!(name, Name::new("CONTENT-LENGTH").unwrap());
}

#[test]
fn separators() {
    assert_eq!(Name::new(""), Err(Error::Empty));
    for text in [
        "Content Length",
        "Host:",
        "a\r\nb",
        "x@y",
        "名字",
        "a/b",
        "a\"b",
    ] {
        assert_eq!(Name::new(text), Err(Error::Character), "{text:?}");
    }
}

#[test]
fn preserved() {
    for bytes in [
        &b"text/html; charset=utf-8"[..],
        b"a\tb",
        b"",
        b"\xe4\xb8\xad",
        b"\xff\x80",
    ] {
        assert_eq!(Value::new(bytes).unwrap().bytes(), bytes);
    }
}

#[test]
fn controls() {
    for bytes in [
        &b"a\r\nb"[..],
        b"a\nb",
        b"a\rb",
        b"a\0b",
        b"a\x7fb",
        b"\x01",
        b"a\x1fb",
    ] {
        assert_eq!(Value::new(bytes), Err(Error::Character), "{bytes:?}");
    }
}

#[test]
fn padding() {
    for bytes in [&b" a"[..], b"a ", b"\ta", b"a\t", b" ", b"\t"] {
        assert_eq!(Value::new(bytes), Err(Error::Padding), "{bytes:?}");
    }
}
