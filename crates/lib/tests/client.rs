#[allow(dead_code)]
mod common;

use common::{Server, client, text};
use osistack::Roots;
use osistack::applied;
use osistack::http::{Method, Uri};
use std::fs;
use std::time::Duration;

fn get() -> Method {
    Method::new("GET").unwrap()
}

#[test]
fn length() {
    let server = Server::replying(text(&[
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Kind: plain\r\n\r\nhello",
    ]));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.head.reason, "OK");
    assert_eq!(response.head.values("x-kind"), vec![&b"plain"[..]]);
    assert_eq!(response.body, b"hello");
}

#[test]
fn wire() {
    let server = Server::replying(text(&["HTTP/1.1 204 No Content\r\n\r\n"]));
    let port = server.port;
    client().fetch(get(), &server.uri, b"").unwrap();
    let seen = String::from_utf8(server.captured()).unwrap();
    let expected =
        format!("GET /path?q=1 HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\nconnection: close\r\n\r\n");
    assert_eq!(seen, expected);
}

#[test]
fn chunked() {
    let server = Server::replying(text(&[
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "5\r\nhello\r\n1;ext=1\r\n \r\n5\r\nworld\r\n0\r\n\r\n",
    ]));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.body, b"hello world");
}

#[test]
fn closing() {
    let server = Server::replying(text(&["HTTP/1.0 200 OK\r\n\r\nuntil ", "the end"]));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.body, b"until the end");
}

#[test]
fn head() {
    let server = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"]));
    let method = Method::new("HEAD").unwrap();
    let response = client().fetch(method, &server.uri, b"").unwrap();
    assert!(response.body.is_empty());
    assert_eq!(response.head.values("content-length"), vec![&b"500"[..]]);
}

#[test]
fn missing() {
    let server = Server::replying(text(&[
        "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\ngone",
    ]));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 404);
    assert_eq!(response.body, b"gone");
}

#[test]
fn interim() {
    let server = Server::replying(text(&[
        "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ]));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
}

#[test]
fn post() {
    let server = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]));
    let method = Method::new("POST").unwrap();
    client().fetch(method, &server.uri, b"payload").unwrap();
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(seen.starts_with("POST /path?q=1 HTTP/1.1\r\n"));
    assert!(seen.contains("content-length: 7\r\n"));
    assert!(seen.ends_with("\r\n\r\npayload"));
}

#[test]
fn empty() {
    let server = Server::replying(text(&["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]));
    let method = Method::new("POST").unwrap();
    client().fetch(method, &server.uri, b"").unwrap();
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(seen.contains("content-length: 0\r\n"));
}

#[test]
fn split() {
    let whole = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nX-A: b\r\n\r\nabcdef";
    let parts = whole.bytes().map(|byte| vec![byte]).collect();
    let server = Server::pausing(parts, Duration::from_millis(1));
    let response = client().fetch(get(), &server.uri, b"").unwrap();
    assert_eq!(response.body, b"abcdef");
    assert_eq!(response.head.values("x-a"), vec![&b"b"[..]]);
}

#[test]
fn differing() {
    if !common::outside::present() {
        return;
    }
    let issued = common::outside::minted();
    let server = common::outside::serving(&issued.cert, &issued.key);
    let mut client = client();
    let text = fs::read_to_string(&issued.cert).unwrap();
    client.roots = Roots::pem(&text).unwrap();
    let port = server.port;
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert!(!response.body.is_empty());
}

#[test]
#[ignore = "network"]
fn smoking() {
    let Ok(url) = std::env::var("OSISTACK_SMOKE_URL") else {
        return;
    };
    let Ok(file) = std::env::var("OSISTACK_SMOKE_CACERT") else {
        return;
    };
    if url.is_empty() || file.is_empty() {
        return;
    }
    if !url.to_ascii_lowercase().starts_with("https://") {
        return;
    }
    let applied = applied(&["--cacert", &file, &url]).unwrap();
    let status = applied.response.head.status.get();
    assert!((100..600).contains(&status), "{status}");
}

#[test]
#[ignore = "nghttpd"]
fn peering() {
    if !common::httpd::present() {
        return;
    }
    let issued = common::outside::minted();
    let server = common::httpd::hosted(&issued);
    let mut client = client();
    let text = fs::read_to_string(&issued.cert).unwrap();
    client.roots = Roots::pem(&text).unwrap();
    let port = server.port;
    let uri = Uri::parse(&format!("https://localhost:{port}/index.html")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
}
