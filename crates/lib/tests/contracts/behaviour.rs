use crate::common::{Server, client, text};
use osistack::http::Method;
use osistack::{Error, h1};

pub type Check = fn();

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("content-length", length as Check),
        ("chunked", chunked as Check),
        ("connection-close", closing as Check),
        ("http10-response", legacy as Check),
        ("status-not-error", status as Check),
        ("framing", framing as Check),
    ]
}

fn get() -> Method {
    Method::new("GET").unwrap()
}

fn body(parts: &[&str]) -> Vec<u8> {
    let server = Server::replying(text(parts));
    client().fetch(get(), &server.uri, b"").unwrap().body
}

fn fails(parts: &[&str]) -> Error {
    let server = Server::replying(text(parts));
    client().fetch(get(), &server.uri, b"").unwrap_err()
}

fn length() {
    let sent = ["HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Kind: plain\r\n\r\nhello"];
    let server = Server::replying(text(&sent));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.head.values("x-kind"), vec![&b"plain"[..]]);
    assert_eq!(response.body, b"hello");
    let short = fails(&["HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"]);
    assert!(matches!(short, Error::Short));
}

fn chunked() {
    let sent = [
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "5\r\nhello\r\n1;ext=1\r\n \r\n5\r\nworld\r\n0\r\n\r\n",
    ];
    assert_eq!(body(&sent), b"hello world");
    let cut = ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"];
    assert!(matches!(fails(&cut), Error::Short));
}

fn closing() {
    let server = Server::replying(text(&["HTTP/1.1 204 No Content\r\n\r\n"]));
    let port = server.port;
    client().fetch(get(), &server.uri, b"").unwrap();
    let seen = String::from_utf8(server.captured()).unwrap();
    let expected =
        format!("GET /path?q=1 HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nconnection: close\r\n\r\n");
    assert_eq!(seen, expected);
    let sent = [
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil ",
        "the end",
    ];
    assert_eq!(body(&sent), b"until the end");
}

fn legacy() {
    let server = Server::replying(text(&["HTTP/1.0 200 OK\r\n\r\nuntil ", "the end"]));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"until the end");
}

fn status() {
    for (line, code) in [
        ("404 Not Found", 404),
        ("500 Oops", 500),
        ("301 Moved", 301),
    ] {
        let sent = format!("HTTP/1.1 {line}\r\nContent-Length: 4\r\n\r\ngone");
        let server = Server::replying(text(&[sent.as_str()]));
        let response = client().fetch(get(), &server.uri, b"").unwrap();
        assert_eq!(response.head.status.get(), code);
        assert_eq!(response.body, b"gone");
    }
}

fn framing() {
    let sized = ["HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"];
    let chunks = ["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"];
    let ended = ["HTTP/1.0 200 OK\r\n\r\nabc"];
    for sent in [&sized[..], &chunks[..], &ended[..]] {
        assert_eq!(body(sent), b"abc");
    }
    let server = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"]));
    let method = Method::new("HEAD").unwrap();
    let response = client().fetch(method, &server.uri, b"").unwrap();
    assert!(response.body.is_empty());
    assert!(body(&["HTTP/1.1 204 No Content\r\n\r\n"]).is_empty());
    let both = ["HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"];
    let outcome = fails(&both);
    assert!(matches!(outcome, Error::Frame(h1::Error::Ambiguous)));
}
