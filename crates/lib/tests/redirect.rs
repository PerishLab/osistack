#[allow(dead_code)]
mod common;

use common::{Server, client, text};
use osistack::Error;
use osistack::http::{Method, Uri};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn get() -> Method {
    Method::new("GET").unwrap()
}

fn post() -> Method {
    Method::new("POST").unwrap()
}

#[test]
fn posted() {
    let dest = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"])).unwrap();
    let location = format!("http://127.0.0.1:{}/keep", dest.port);
    let head = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
    );
    let src = Server::replying(text(&[&head])).unwrap();
    let response = client().fetch(post(), &src.uri, b"hi").unwrap();
    assert_eq!(response.head.status.get(), 200);
    let seen = String::from_utf8(dest.captured()).unwrap();
    let _ = src.captured();
    assert!(seen.starts_with("POST /keep HTTP/1.1\r\n"), "{seen}");
    assert!(seen.ends_with("\r\n\r\nhi"), "{seen}");
}

#[test]
fn rewritten() {
    let dest = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"])).unwrap();
    let location = format!("http://127.0.0.1:{}/next", dest.port);
    let head = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
    let src = Server::replying(text(&[&head])).unwrap();
    let response = client().fetch(post(), &src.uri, b"hi").unwrap();
    assert_eq!(response.head.status.get(), 200);
    let seen = String::from_utf8(dest.captured()).unwrap();
    let _ = src.captured();
    assert!(seen.starts_with("GET /next HTTP/1.1\r\n"), "{seen}");
    assert!(!seen.contains("content-length"), "{seen}");
}

#[test]
fn https() {
    let head = "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n";
    let src = Server::replying(text(&[head])).unwrap();
    let outcome = client().fetch(get(), &src.uri, b"");
    let _ = src.captured();
    assert!(matches!(outcome, Err(Error::Socket(_))), "{outcome:?}");
}

#[test]
fn missing() {
    let src = Server::replying(text(&["HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"])).unwrap();
    let response = client().fetch(get(), &src.uri, b"").unwrap();
    let _ = src.captured();
    assert_eq!(response.head.status.get(), 302);
}

#[test]
fn looped() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let location = format!("http://127.0.0.1:{port}/path");
    let handle = thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = peer.read(&mut buf);
        let reply =
            format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
        let _ = peer.write_all(reply.as_bytes());
    });
    let uri = Uri::parse(&format!("http://127.0.0.1:{port}/path")).unwrap();
    let outcome = client().fetch(get(), &uri, b"");
    handle.join().unwrap();
    assert!(matches!(outcome, Err(Error::Redirect)));
}

#[test]
fn bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        for hop in 0..6 {
            let (mut peer, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = peer.read(&mut buf);
            let location = format!("http://127.0.0.1:{port}/h{}", hop + 1);
            let reply =
                format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
            let _ = peer.write_all(reply.as_bytes());
        }
    });
    let uri = Uri::parse(&format!("http://127.0.0.1:{port}/h0")).unwrap();
    let outcome = client().fetch(get(), &uri, b"");
    handle.join().unwrap();
    assert!(matches!(outcome, Err(Error::Redirect)));
}
