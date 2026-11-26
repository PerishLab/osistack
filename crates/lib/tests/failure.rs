#[allow(dead_code)]
mod common;

use common::{Server, client, text};
use osistack::http::{Method, Uri};
use osistack::socket::{Error as Socket, Phase};
use osistack::{Client, Error, h1};
use std::net::TcpListener;
use std::time::Duration;

fn get() -> Method {
    Method::new("GET").unwrap()
}

#[test]
fn refused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let uri = Uri::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let outcome = client().fetch(get(), &uri, b"");
    assert!(matches!(outcome, Err(Error::Socket(Socket::Connect(_)))));
}

#[test]
fn silent() {
    let server = Server::silent(Duration::from_millis(600)).unwrap();
    let patient = Client {
        read: Duration::from_millis(150),
        ..client()
    };
    let outcome = patient.fetch(get(), &server.uri, b"");
    assert!(matches!(
        outcome,
        Err(Error::Socket(Socket::Timeout(Phase::Read)))
    ));
}

#[test]
fn scheme() {
    let uri = Uri::parse("https://127.0.0.1:1/").unwrap();
    let outcome = client().fetch(get(), &uri, b"");
    #[cfg(target_os = "linux")]
    assert!(matches!(outcome, Err(Error::Socket(Socket::Connect(_)))));
    #[cfg(not(target_os = "linux"))]
    assert!(matches!(outcome, Err(Error::Trust)));
}

#[test]
fn oversize() {
    let server =
        Server::replying(text(&["HTTP/1.1 200 OK\r\nX-Long: ", &"a".repeat(300)])).unwrap();
    let small = Client {
        head: 64,
        ..client()
    };
    let outcome = small.fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Frame(h1::Error::Size))));
}

#[test]
fn heavy() {
    let server =
        Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"])).unwrap();
    let small = Client {
        body: 10,
        ..client()
    };
    let outcome = small.fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Limit)));
}

#[test]
fn endless() {
    let parts = text(&["HTTP/1.0 200 OK\r\n\r\n", &"x".repeat(100)]);
    let server = Server::replying(parts).unwrap();
    let small = Client {
        body: 10,
        ..client()
    };
    let outcome = small.fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Limit)));
}

#[test]
fn pieces() {
    let parts = text(&[
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        &"1\r\nx\r\n".repeat(50),
    ]);
    let server = Server::replying(parts).unwrap();
    let small = Client {
        body: 20,
        ..client()
    };
    let outcome = small.fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Limit)));
}

#[test]
fn bulky() {
    let body = "a".repeat(100);
    let reply =
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n{body}\r\n0\r\n\r\n");
    let server = Server::replying(text(&[&reply])).unwrap();
    let small = Client {
        body: 10,
        ..client()
    };
    let outcome = small.fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Limit)));
}

#[test]
fn early() {
    let server =
        Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"])).unwrap();
    let outcome = client().fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Short)));
}

#[test]
fn headless() {
    let server = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-"])).unwrap();
    let outcome = client().fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Short)));
}

#[test]
fn truncated() {
    let server = Server::replying(text(&[
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
    ]))
    .unwrap();
    let outcome = client().fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Short)));
}

#[test]
fn ambiguous() {
    let server = Server::replying(text(&[
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
    ]))
    .unwrap();
    let outcome = client().fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Frame(h1::Error::Ambiguous))));
}

#[test]
fn malformed() {
    let server = Server::replying(text(&["NOT HTTP\r\n\r\n"])).unwrap();
    let outcome = client().fetch(get(), &server.uri, b"");
    assert!(matches!(outcome, Err(Error::Frame(_))));
}

#[test]
fn display() {
    let outcome = Error::Short.to_string();
    assert!(outcome.contains("closed"));
}

#[test]
fn wording() {
    use std::error::Error as Std;
    let frame = Error::Frame(h1::Error::Size);
    let text = frame.to_string();
    assert!(text.contains(&h1::Error::Size.to_string()));
    assert!(!text.contains("Size"));
    assert_eq!(
        frame.source().map(ToString::to_string),
        Some(h1::Error::Size.to_string())
    );
}
