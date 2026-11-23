mod edges;
mod support;

use h2::Header;
use osistack::Pool;
use osistack::http::{Method, Uri};
use support::{PREFACE, get, local, reply, spawn};

#[test]
fn fetch() {
    let (port, server) = spawn(|stream| reply(stream, b"GET", &[b"ok".as_slice()]).2);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = local().fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    assert!(server.join().unwrap().starts_with(PREFACE));
}

#[test]
fn pooling() {
    let (port, server) =
        spawn(|stream| reply(stream, b"GET", &[b"a".as_slice(), b"b".as_slice()]).2);
    let one = Uri::parse(&format!("https://localhost:{port}/one")).unwrap();
    let two = Uri::parse(&format!("https://localhost:{port}/two")).unwrap();
    let mut pool = Pool::new(local());
    assert_eq!(pool.fetch(get(), &one, b"").unwrap().body, b"a");
    assert_eq!(pool.fetch(get(), &two, b"").unwrap().body, b"b");
    assert!(server.join().unwrap().starts_with(PREFACE));
}

#[test]
fn posting() {
    let (port, server) = spawn(|stream| reply(stream, b"POST", &[b"ok".as_slice()]));
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let method = Method::new("POST").unwrap();
    let response = local().fetch(method, &uri, b"hello").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let (fields, data, seen) = server.join().unwrap();
    assert!(
        fields.contains(&Header::new(b":method", b"POST")),
        "{fields:?}"
    );
    assert!(
        fields.contains(&Header::new(b":path", b"/path")),
        "{fields:?}"
    );
    assert_eq!(data, b"hello");
    assert!(seen.starts_with(PREFACE), "{seen:?}");
}
