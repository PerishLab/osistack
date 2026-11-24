#[path = "peer.rs"]
mod peer;

use osistack::http::{Method, Uri};
use osistack::{Client, Http3};
use peer::serve;
use std::time::Duration;

fn client(roots: tls::x509::trust::Roots, http3: Http3) -> Client {
    Client {
        connect: Duration::from_secs(2),
        read: Duration::from_secs(2),
        write: Duration::from_secs(2),
        total: Duration::from_secs(5),
        roots,
        http3,
        ..Client::default()
    }
}

fn get() -> Method {
    Method::new("GET").unwrap()
}

fn post() -> Method {
    Method::new("POST").unwrap()
}

#[test]
fn only() {
    let peer = serve();
    let uri = Uri::parse(&format!("{}/hello", peer.uri)).unwrap();
    let response = client(peer.roots.clone(), Http3::Only)
        .fetch(get(), &uri, b"")
        .unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"hello");
}

#[test]
fn posted() {
    let peer = serve();
    let uri = Uri::parse(&format!("{}/echo", peer.uri)).unwrap();
    let response = client(peer.roots.clone(), Http3::Only)
        .fetch(post(), &uri, b"ping")
        .unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ping");
}

#[test]
fn prefer() {
    let peer = serve();
    let uri = Uri::parse(&format!("{}/hello", peer.uri)).unwrap();
    let response = client(peer.roots.clone(), Http3::Prefer)
        .fetch(get(), &uri, b"")
        .unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"hello");
}
