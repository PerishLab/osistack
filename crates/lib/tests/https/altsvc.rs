use super::h3peer::serve;
use super::support::{announce, begin, get, local, mint, twice};
use osistack::Pool;
use osistack::http::Uri;

fn port(uri: &str) -> u16 {
    Uri::parse(uri).unwrap().port()
}

#[test]
fn later() {
    let held = mint("localhost");
    let peer = serve();
    let alt = port(&peer.uri);
    let (port, server) = begin(move |stream| announce(stream, alt));
    let client = local(held.roots);
    let first = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = client.fetch(get(), &first, b"").unwrap();
    assert_eq!(response.body, b"ok");
    let next = Uri::parse(&format!("https://localhost:{port}/hello")).unwrap();
    let response = client.fetch(get(), &next, b"").unwrap();
    assert_eq!(response.body, b"hello");
    let _ = server.join();
}

#[test]
fn clear() {
    let held = mint("localhost");
    let (port, server) = twice(move |stream| announce(stream, 1));
    let client = local(held.roots);
    let first = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    assert_eq!(client.fetch(get(), &first, b"").unwrap().body, b"ok");
    client.clear();
    let next = Uri::parse(&format!("https://localhost:{port}/hello")).unwrap();
    assert_eq!(client.fetch(get(), &next, b"").unwrap().body, b"ok");
    let _ = server.join();
}

#[test]
fn pooled() {
    let held = mint("localhost");
    let peer = serve();
    let alt = port(&peer.uri);
    let (port, server) = begin(move |stream| announce(stream, alt));
    let mut pool = Pool::new(local(held.roots));
    let first = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    assert_eq!(pool.fetch(get(), &first, b"").unwrap().body, b"ok");
    let next = Uri::parse(&format!("https://localhost:{port}/hello")).unwrap();
    assert_eq!(pool.fetch(get(), &next, b"").unwrap().body, b"hello");
    let _ = server.join();
}
