use h1::{Error, Head, Version};

fn parse(text: &str) -> Result<Option<(Head, usize)>, Error> {
    Head::parse(text.as_bytes(), 8192)
}

fn ok(text: &str) -> Head {
    parse(text).unwrap().unwrap().0
}

#[test]
fn minimal() {
    let text = "HTTP/1.1 200 OK\r\n\r\n";
    let (head, used) = parse(text).unwrap().unwrap();
    assert_eq!(head.version, Version::Http11);
    assert_eq!(head.status.get(), 200);
    assert_eq!(head.reason, "OK");
    assert!(head.fields.is_empty());
    assert_eq!(used, text.len());
}

#[test]
fn legacy() {
    let head = ok("HTTP/1.0 404 Not Found\r\n\r\n");
    assert_eq!(head.version, Version::Http10);
    assert_eq!(head.status.get(), 404);
    assert_eq!(head.reason, "Not Found");
}

#[test]
fn fields() {
    let head = ok(
        "HTTP/1.1 200 OK\r\nHost: example.com\r\nSet-Cookie: a=1\r\nset-cookie:\t b=2 \t\r\nEmpty:\r\n\r\n",
    );
    assert_eq!(head.fields.len(), 4);
    assert_eq!(head.fields[0].name.text(), "host");
    assert_eq!(head.fields[0].value.bytes(), b"example.com");
    assert_eq!(head.values("Set-Cookie"), [&b"a=1"[..], b"b=2"]);
    assert_eq!(head.values("empty"), [&b""[..]]);
}

#[test]
fn consumed() {
    let text = "HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody";
    let (_, used) = parse(text).unwrap().unwrap();
    assert_eq!(&text[used..], "body");
}

#[test]
fn reason() {
    assert_eq!(ok("HTTP/1.1 204\r\n\r\n").reason, "");
    assert_eq!(ok("HTTP/1.1 204 \r\n\r\n").reason, "");
    assert_eq!(
        ok("HTTP/1.1 200 Fine\tindeed\r\n\r\n").reason,
        "Fine\tindeed"
    );
}

#[test]
fn incomplete() {
    let text = "HTTP/1.1 200 OK\r\nA: b\r\n\r\n";
    for cut in 0..text.len() {
        assert_eq!(parse(&text[..cut]), Ok(None), "{cut}");
    }
}

#[test]
fn oversized() {
    let text = "HTTP/1.1 200 OK\r\nA: b\r\n\r\n";
    assert_eq!(
        Head::parse(text.as_bytes(), text.len()).map(|head| head.is_some()),
        Ok(true)
    );
    assert_eq!(
        Head::parse(text.as_bytes(), text.len() - 1),
        Err(Error::Size)
    );
    assert_eq!(Head::parse(&text.as_bytes()[..10], 9), Err(Error::Size));
    assert_eq!(Head::parse(&text.as_bytes()[..10], 10), Ok(None));
}

#[test]
fn newline() {
    assert_eq!(parse("HTTP/1.1 200 OK\n\n"), Err(Error::Line));
    assert_eq!(parse("HTTP/1.1 200 OK\r\nA: b\n\r\n"), Err(Error::Line));
    assert_eq!(
        parse("HTTP/1.1 200 OK\r\nA: b\rc\r\n\r\n"),
        Err(Error::Line)
    );
    assert_eq!(parse("HTTP/1.1 200 OK\n"), Err(Error::Line));
}

#[test]
fn version() {
    assert_eq!(parse("HTTP/2.0 200 OK\r\n\r\n"), Err(Error::Version));
    assert_eq!(parse("HTTP/0.9 200 OK\r\n\r\n"), Err(Error::Version));
    assert_eq!(parse("HTTP/1.2 200 OK\r\n\r\n"), Err(Error::Version));
    assert_eq!(parse("ICY 200 OK\r\n\r\n"), Err(Error::Line));
    assert_eq!(parse("http/1.1 200 OK\r\n\r\n"), Err(Error::Line));
}

#[test]
fn malformed() {
    for text in [
        "HTTP/1.1\r\n\r\n",
        "HTTP/1.1200 OK\r\n\r\n",
        "HTTP/1.1 200OK\r\n\r\n",
        "HTTP/1.1 200 O\u{1}K\r\n\r\n",
    ] {
        assert_eq!(parse(text), Err(Error::Line), "{text:?}");
    }
    for text in [
        "HTTP/1.1 2x0 OK\r\n\r\n",
        "HTTP/1.1  200 OK\r\n\r\n",
        "HTTP/1.1 20 OK\r\n\r\n",
        "HTTP/1.1 099 OK\r\n\r\n",
        "HTTP/1.1 600 OK\r\n\r\n",
    ] {
        assert_eq!(parse(text), Err(Error::Status), "{text:?}");
    }
}

#[test]
fn space() {
    assert_eq!(
        parse("HTTP/1.1 200 OK\r\nHost : x\r\n\r\n"),
        Err(Error::Space)
    );
    assert_eq!(
        parse("HTTP/1.1 200 OK\r\nHost\t: x\r\n\r\n"),
        Err(Error::Space)
    );
}

#[test]
fn fold() {
    assert_eq!(
        parse("HTTP/1.1 200 OK\r\nA: b\r\n c\r\n\r\n"),
        Err(Error::Fold)
    );
    assert_eq!(
        parse("HTTP/1.1 200 OK\r\nA: b\r\n\tc\r\n\r\n"),
        Err(Error::Fold)
    );
    assert_eq!(parse("HTTP/1.1 200 OK\r\n a: b\r\n\r\n"), Err(Error::Fold));
}

#[test]
fn invalid() {
    for text in [
        "HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
        "HTTP/1.1 200 OK\r\n: value\r\n\r\n",
        "HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nA: b\u{0}c\r\n\r\n",
        "HTTP/1.1 200 OK\r\nA: b\u{7f}\r\n\r\n",
    ] {
        assert_eq!(parse(text), Err(Error::Field), "{text:?}");
    }
}
