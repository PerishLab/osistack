use super::support::{
    Aead, Content, Kind, Layer, Message, RANDOM, SECRET, agreed, answer, ending, frame, get, keys,
    local, mint, offered, pull, push, spawn, speak,
};
use osistack::Error;
use osistack::http::Uri;
use std::net::TcpStream;

fn note() -> &'static str {
    "this fixture does not choose the h2 test-peer shape"
}

fn failed(work: fn(TcpStream) -> Vec<u8>) -> Error {
    let held = mint("localhost");
    let (port, server) = spawn(work);
    let client = local(held.roots);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let err = client.fetch(get(), &uri, b"").unwrap_err();
    let _ = server.join();
    err
}

#[test]
fn notified() {
    let held = mint("localhost");
    let (port, server) = spawn(ending);
    let client = local(held.roots);
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200, "{}", note());
    assert_eq!(response.body, b"ok");
    let _ = server.join();
}

#[test]
fn silent() {
    let err = failed(quiet);
    assert!(matches!(err, Error::Short), "{err:?} {}", note());
}

fn quiet(mut stream: TcpStream) -> Vec<u8> {
    let (hello, waiting, _) = speak(&mut stream);
    let (mut send, _) = keys(&hello, &waiting);
    let alert = send.protect(Content::Alert, &[1, 0], 0).unwrap();
    push(&mut stream, &alert);
    Vec::new()
}

#[test]
fn fatal() {
    let err = failed(killed);
    assert!(
        matches!(err, Error::Tls(tls::Error::Kind)),
        "{err:?} {}",
        note()
    );
}

fn killed(mut stream: TcpStream) -> Vec<u8> {
    let (hello, waiting, _) = speak(&mut stream);
    let (mut send, _) = keys(&hello, &waiting);
    let alert = send.protect(Content::Alert, &[2, 40], 0).unwrap();
    push(&mut stream, &alert);
    Vec::new()
}

#[test]
fn early() {
    let err = failed(plain);
    assert!(
        matches!(err, Error::Tls(tls::Error::Kind)),
        "{err:?} {}",
        note()
    );
}

fn plain(mut peer: TcpStream) -> Vec<u8> {
    let _ = pull(&mut peer, &mut Vec::new());
    push(&mut peer, &frame(Content::Alert, vec![2, 40]));
    Vec::new()
}

#[test]
fn flight() {
    let err = failed(shifted);
    assert!(
        matches!(err, Error::Tls(tls::Error::Kind)),
        "{err:?} {}",
        note()
    );
}

fn shifted(mut peer: TcpStream) -> Vec<u8> {
    let hello = offered(&mut peer);
    let held = mint("localhost");
    let (reply, _, _) = answer(&hello, &held, &SECRET, RANDOM).unwrap();
    push(
        &mut peer,
        &frame(
            Content::Handshake,
            Message {
                kind: Kind::Reply,
                body: reply.write().unwrap(),
            }
            .write()
            .unwrap(),
        ),
    );
    let accepted = hello.accept(&reply, &agreed(&hello)).unwrap();
    let keys = accepted.server().keys(Aead::Aes128).unwrap();
    let mut layer = Layer::new(Aead::Aes128, &keys).unwrap();
    let alert = layer.protect(Content::Alert, &[2, 40], 0).unwrap();
    push(&mut peer, &alert);
    Vec::new()
}
