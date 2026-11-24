#[path = "peer.rs"]
mod peer;

use crate::common::certs;
use osistack::http::{Method, Uri};
use osistack::{Client, Http3, command};
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

fn stored(der: &[u8], flag: &str) -> std::path::PathBuf {
    let tag = flag.trim_start_matches('-');
    let path = std::env::temp_dir().join(format!("osistack-334-{}-{tag}", std::process::id()));
    std::fs::write(&path, certs(der)).unwrap();
    path
}

fn flagged(flag: &str) {
    let peer = serve();
    let path = stored(&peer.der, flag);
    let target = format!("{}/hello", peer.uri);
    let response = command(&[flag, "--cacert", path.to_str().unwrap(), &target]).unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"hello");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn http3() {
    flagged("--http3");
}

#[test]
fn sole() {
    flagged("--http3-only");
}
