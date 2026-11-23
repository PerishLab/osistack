use h1::{Chunked, Error, Field, Framing, Request};
use http::{Method, Name, Value};

fn field(name: &str, value: &str) -> Field {
    Field {
        name: Name::new(name).unwrap(),
        value: Value::new(value.as_bytes()).unwrap(),
    }
}

fn build(method: &str, target: &str, fields: &[(&str, &str)]) -> Result<Request, Error> {
    let list = fields
        .iter()
        .map(|(name, value)| field(name, value))
        .collect();
    Request::new(Method::new(method).unwrap(), target, list)
}

fn encode(method: &str, target: &str, fields: &[(&str, &str)]) -> Result<Vec<u8>, Error> {
    build(method, target, fields)?.encode()
}

#[test]
fn minimal() {
    let out = encode("GET", "/", &[("Host", "example.com")]).unwrap();
    assert_eq!(out, b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n");
}

#[test]
fn order() {
    let fields = [("Host", "a"), ("Accept", "*/*"), ("X-B", "2"), ("X-A", "1")];
    let out = encode("POST", "/p?q=1", &fields).unwrap();
    let text = "POST /p?q=1 HTTP/1.1\r\nhost: a\r\naccept: */*\r\nx-b: 2\r\nx-a: 1\r\n\r\n";
    assert_eq!(out, text.as_bytes());
}

#[test]
fn targets() {
    let host = [("Host", "example.com")];
    for target in ["/", "/a/b?c=d", "*", "http://example.com/x"] {
        let out = encode("OPTIONS", target, &host).unwrap();
        assert!(
            out.starts_with(format!("OPTIONS {target} HTTP/1.1\r\n").as_bytes()),
            "{target}"
        );
    }
}

#[test]
fn hostile() {
    for target in [
        "",
        "/a b",
        "/a\r\nHost: x",
        "/a\tb",
        "/\u{7f}",
        "/名字",
        "\u{0}",
    ] {
        assert_eq!(
            build("GET", target, &[("Host", "a")]),
            Err(Error::Target),
            "{target:?}"
        );
    }
}

#[test]
fn hosts() {
    assert_eq!(encode("GET", "/", &[]), Err(Error::Host));
    assert_eq!(encode("GET", "/", &[("Accept", "*/*")]), Err(Error::Host));
    assert_eq!(
        encode("GET", "/", &[("Host", "a"), ("host", "b")]),
        Err(Error::Host)
    );
}

#[test]
fn empty() {
    let request = build("GET", "/", &[("Host", "a")]).unwrap();
    assert_eq!(request.framing(), Ok(Framing::Empty));
}

#[test]
fn sized() {
    let fields = [("Host", "a"), ("Content-Length", "5")];
    assert_eq!(
        build("POST", "/", &fields).unwrap().framing(),
        Ok(Framing::Length(5))
    );
    let fields = [("Host", "a"), ("Content-Length", "5, 5")];
    assert_eq!(
        build("POST", "/", &fields).unwrap().framing(),
        Ok(Framing::Length(5))
    );
}

#[test]
fn merged() {
    let fields = [
        ("Host", "a"),
        ("Content-Length", "7"),
        ("X", "y"),
        ("Content-Length", "7"),
    ];
    let out = encode("POST", "/", &fields).unwrap();
    assert_eq!(
        out,
        b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 7\r\nx: y\r\n\r\n"
    );
}

#[test]
fn chunked() {
    let fields = [("Host", "a"), ("Transfer-Encoding", "gzip, chunked")];
    assert_eq!(
        build("POST", "/", &fields).unwrap().framing(),
        Ok(Framing::Chunked)
    );
    assert!(encode("POST", "/", &fields).is_ok());
}

#[test]
fn smuggling() {
    let both = [
        ("Host", "a"),
        ("Content-Length", "5"),
        ("Transfer-Encoding", "chunked"),
    ];
    assert_eq!(encode("POST", "/", &both), Err(Error::Ambiguous));
    let other = [
        ("Host", "a"),
        ("Transfer-Encoding", "gzip"),
        ("Content-Length", "5"),
    ];
    assert_eq!(encode("POST", "/", &other), Err(Error::Ambiguous));
}

#[test]
fn lengths() {
    for value in ["", "+5", "5x", "-1", "1.5", "5, 6", "18446744073709551616"] {
        let fields = [("Host", "a"), ("Content-Length", value)];
        assert_eq!(
            encode("POST", "/", &fields),
            Err(Error::Length),
            "{value:?}"
        );
    }
    let split = [
        ("Host", "a"),
        ("Content-Length", "5"),
        ("Content-Length", "6"),
    ];
    assert_eq!(encode("POST", "/", &split), Err(Error::Length));
}

#[test]
fn encodings() {
    for value in ["gzip", "chunked, gzip", "chunked, chunked", "", ","] {
        let fields = [("Host", "a"), ("Transfer-Encoding", value)];
        assert_eq!(
            encode("POST", "/", &fields),
            Err(Error::Encoding),
            "{value:?}"
        );
    }
}

#[test]
fn blocks() {
    assert_eq!(Chunked::encode(b"hello"), b"5\r\nhello\r\n");
    assert_eq!(Chunked::encode(&[0u8; 26]).get(..4), Some(&b"1a\r\n"[..]));
    assert_eq!(Chunked::encode(&[]), Vec::<u8>::new());
    assert_eq!(Chunked::finish(), b"0\r\n\r\n");
}

#[test]
fn roundtrip() {
    let parts: [&[u8]; 4] = [b"hello", b"", b" world", &[0, 255, 13, 10]];
    let mut wire = Vec::new();
    for part in parts {
        wire.extend(Chunked::encode(part));
    }
    wire.extend(Chunked::finish());
    let body = Chunked::decode(&wire).unwrap().unwrap();
    assert_eq!(body.data, b"hello world\x00\xff\r\n");
    assert_eq!(body.used, wire.len());
}

#[test]
fn connect() {
    let host = [("Host", "example.com:443")];
    let out = encode("CONNECT", "example.com:443", &host).unwrap();
    assert_eq!(
        out,
        b"CONNECT example.com:443 HTTP/1.1\r\nhost: example.com:443\r\n\r\n"
    );
    let out = encode("CONNECT", "[::1]:8443", &[("Host", "[::1]:8443")]).unwrap();
    assert!(out.starts_with(b"CONNECT [::1]:8443 HTTP/1.1\r\n"));
}

#[test]
fn absolute() {
    let host = [("Host", "example.com")];
    let target = "https://example.com:8443/x?y=1";
    let out = encode("GET", target, &host).unwrap();
    assert!(out.starts_with(format!("GET {target} HTTP/1.1\r\n").as_bytes()));
}

#[test]
fn forms() {
    let host = [("Host", "a")];
    for target in ["/", "http://a/", "*", "example.com"] {
        assert_eq!(
            build("CONNECT", target, &host),
            Err(Error::Target),
            "{target}"
        );
    }
    assert_eq!(build("GET", "*", &host), Err(Error::Target));
    assert_eq!(build("GET", "example.com:443", &host), Err(Error::Target));
    assert_eq!(build("CONNECT", "example.com:0", &host), Err(Error::Target));
    assert_eq!(build("CONNECT", "http://a:443/", &host), Err(Error::Target));
    assert_eq!(build("GET", "http://user@a/", &host), Err(Error::Target));
    assert_eq!(build("GET", "http://a/#frag", &host), Err(Error::Target));
}

#[test]
fn parsed() {
    let request = build("CONNECT", "example.com:443", &[("Host", "example.com:443")]).unwrap();
    let bytes = request.encode().unwrap();
    let (found, used) = Request::parse(&bytes, 4096).unwrap().unwrap();
    assert_eq!((found, used), (request, bytes.len()));
    let request = build("GET", "http://example.com/x", &[("Host", "example.com")]).unwrap();
    let bytes = request.encode().unwrap();
    let (found, used) = Request::parse(&bytes, 4096).unwrap().unwrap();
    assert_eq!((found, used), (request, bytes.len()));
}

#[test]
fn prefixes() {
    let bytes = encode("GET", "http://a/x", &[("Host", "a")]).unwrap();
    assert!(Request::parse(&bytes, 4096).unwrap().is_some());
    for size in 0..bytes.len() {
        assert_eq!(Request::parse(&bytes[..size], 4096), Ok(None), "{size}");
    }
    assert_eq!(Request::parse(&bytes, bytes.len() - 1), Err(Error::Size));
}

#[test]
fn lining() {
    assert_eq!(
        Request::parse(b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 4096),
        Err(Error::Version)
    );
    assert_eq!(
        Request::parse(b"GET / extra HTTP/1.1\r\nHost: a\r\n\r\n", 4096),
        Err(Error::Line)
    );
    assert_eq!(Request::parse(&[], 4096), Ok(None));
}
