mod alerts;
mod support;

mod tls {
    pub(crate) use crate::support::{Held, mint, spoken};
}

#[allow(dead_code)]
#[path = "../contracts/http3/peer.rs"]
mod h3peer;

mod altsvc;

use osistack::http::{Method, Uri};
use osistack::{Client, Http3, Pool};
use support::{certs, command, driven, get, local, mint, reused, serve, spawn};

#[test]
fn fetch() {
    let held = mint("localhost");
    let (port, server) = spawn(serve);
    let client = local(held.roots);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
    assert!(
        seen.contains(&format!("host: localhost:{port}\r\n")),
        "{seen}"
    );
}

#[test]
fn posting() {
    let held = mint("localhost");
    let (port, server) = spawn(serve);
    let client = local(held.roots);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let method = Method::new("POST").unwrap();
    let response = client.fetch(method, &uri, b"hello").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(seen.starts_with("POST /path HTTP/1.1\r\n"), "{seen}");
    assert!(
        seen.contains(&format!("host: localhost:{port}\r\n")),
        "{seen}"
    );
    assert!(seen.contains("content-length: 5\r\n"), "{seen}");
    assert!(seen.ends_with("\r\n\r\nhello"), "{seen}");
}

#[test]
fn roots() {
    let (port, server) = spawn(serve);
    let client = local(osistack::Roots::default());
    let uri = Uri::parse(&format!("https://localhost:{port}/")).unwrap();
    let outcome = client.fetch(get(), &uri, b"");
    assert!(
        matches!(outcome, Err(osistack::Error::Tls(_))),
        "{outcome:?}"
    );
    let _ = server.join();
}

#[test]
fn pooling() {
    let held = mint("localhost");
    let (port, server) = spawn(reused);
    let client = local(held.roots);
    let one = Uri::parse(&format!("https://localhost:{port}/one")).unwrap();
    let two = Uri::parse(&format!("https://localhost:{port}/two")).unwrap();
    let mut pool = Pool::new(client);
    assert_eq!(pool.fetch(get(), &one, b"").unwrap().body, b"a");
    assert_eq!(pool.fetch(get(), &two, b"").unwrap().body, b"b");
    let seen = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(seen.contains("GET /one HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("GET /two HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("connection: keep-alive\r\n"), "{seen}");
}

#[test]
fn commanding() {
    let held = mint("localhost");
    let (port, server) = spawn(serve);
    let target = format!("https://localhost:{port}/path");
    let der = held.der.clone();
    let response = driven(local(held.roots), &[&target]).unwrap().response;
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
    let path = std::env::temp_dir().join(format!("osistack-276-{}", std::process::id()));
    std::fs::write(&path, certs(&der)).unwrap();
    let (port, server) = spawn(serve);
    let target = format!("https://localhost:{port}/path");
    let response = command(&["--cacert", path.to_str().unwrap(), &target]).unwrap();
    assert_eq!(response.body, b"ok");
    let _ = server.join();
    let _ = std::fs::remove_file(&path);
}

fn brief(roots: osistack::Roots, http3: Http3) -> Client {
    let wait = std::time::Duration::from_millis(300);
    Client {
        roots,
        connect: wait,
        read: wait,
        write: wait,
        total: std::time::Duration::from_secs(2),
        http3,
        ..Client::default()
    }
}

#[test]
fn prefer() {
    let held = mint("localhost");
    let (port, server) = spawn(serve);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = brief(held.roots, Http3::Prefer)
        .fetch(get(), &uri, b"")
        .unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(seen.starts_with("GET /path HTTP/1.1\r\n"), "{seen}");
}

#[test]
fn only() {
    let held = mint("localhost");
    let (port, server) = spawn(serve);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let outcome = brief(held.roots, Http3::Only).fetch(get(), &uri, b"");
    assert!(outcome.is_err(), "{outcome:?}");
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    let _ = server.join();
}
