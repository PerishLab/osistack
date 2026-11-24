#[allow(dead_code, unused_imports)]
#[path = "../common/mod.rs"]
mod common;
#[allow(dead_code)]
#[path = "../contracts/tls/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "../contracts/tls/sign.rs"]
mod sign;

use crypto::{Group, Hash};
use osistack::Client;
use osistack::http::Method;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub(crate) use common::certs;
pub(crate) use crypto::Aead;
pub(crate) use osistack::{Roots, command, driven};
pub(crate) use peer::{Held, Waiting, answer, frame, mint, spoken};
pub(crate) use tls::{Content, Hello, Kind, Layer, Message, Place, Record, Share, Typed};

pub(crate) const SECRET: [u8; 32] = [8; 32];
pub(crate) const RANDOM: [u8; 32] = [5; 32];

pub(crate) fn get() -> Method {
    Method::new("GET").unwrap()
}

fn sized(seen: &[u8]) -> Option<(usize, usize)> {
    let start = seen.windows(4).position(|part| part == b"\r\n\r\n")?;
    let end = start + 4;
    let head = std::str::from_utf8(&seen[..start]).ok()?;
    let line = head
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("content-length:"))?;
    let size = line[15..].trim().parse().ok()?;
    Some((end, size))
}

pub(crate) fn pull(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Record {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((record, used)) = Record::parse(buffer).unwrap() {
            buffer.drain(..used);
            return record;
        }
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0);
        buffer.extend_from_slice(&chunk[..read]);
    }
}

pub(crate) fn push(stream: &mut TcpStream, record: &Record) {
    stream.write_all(&record.write().unwrap()).unwrap();
}

fn taken(hello: &Hello) -> Share {
    let mut found = None;
    for item in &hello.offer().extensions {
        if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer).unwrap() {
            found = items.into_iter().next();
        }
    }
    found.unwrap()
}

pub(crate) fn agreed(hello: &Hello) -> Vec<u8> {
    let share = taken(hello);
    let group = match share.group {
        0x001d => Group::X25519,
        0x0017 => Group::Secp256r1,
        _ => panic!("group"),
    };
    group.agree(&SECRET, &share.key).unwrap()
}

pub(crate) fn keys(hello: &Hello, waiting: &Waiting) -> (Layer, Layer) {
    let master = tls::Schedule::new(Hash::Sha256, &agreed(hello))
        .unwrap()
        .master()
        .unwrap();
    let digest = waiting.digest();
    let send = master.server(&digest).unwrap().keys(Aead::Aes128).unwrap();
    let recv = master.client(&digest).unwrap().keys(Aead::Aes128).unwrap();
    (
        Layer::new(Aead::Aes128, &send).unwrap(),
        Layer::new(Aead::Aes128, &recv).unwrap(),
    )
}

pub(crate) fn speak(peer: &mut TcpStream) -> (Hello, Waiting, Vec<u8>) {
    let held = mint("localhost");
    let mut buffer = Vec::new();
    let first = pull(peer, &mut buffer);
    assert_eq!(first.content, Content::Handshake);
    let hello = Hello::offered(&first.fragment).unwrap();
    let (reply, records, waiting) = answer(&hello, &held, &SECRET, RANDOM).unwrap();
    push(
        peer,
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
    for record in &records {
        push(peer, record);
    }
    let last = pull(peer, &mut buffer);
    let spoken = waiting.open(&last).unwrap();
    waiting.check(&spoken).unwrap();
    (hello, waiting, buffer)
}

pub(crate) fn serve(stream: TcpStream) -> Vec<u8> {
    finish(stream, false, None)
}

pub(crate) fn ending(stream: TcpStream) -> Vec<u8> {
    finish(stream, true, None)
}

pub(crate) fn announce(stream: TcpStream, alt: u16) -> Vec<u8> {
    finish(stream, false, Some(alt))
}

fn finish(mut stream: TcpStream, close: bool, alt: Option<u16>) -> Vec<u8> {
    let (hello, waiting, mut buffer) = speak(&mut stream);
    let (mut send, mut recv) = keys(&hello, &waiting);
    let mut seen = Vec::new();
    loop {
        let record = pull(&mut stream, &mut buffer);
        let opened = recv.unprotect(&record).unwrap();
        if opened.content != Content::Application {
            continue;
        }
        seen.extend(opened.payload);
        if let Some((end, size)) = sized(&seen) {
            if seen.len() >= end + size {
                break;
            }
        } else if seen.windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }
    }
    let body = b"ok";
    let extra = alt
        .map(|port| format!("alt-svc: h3=\":{port}\"\r\n"))
        .unwrap_or_default();
    let reply = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
        body.len()
    );
    let mut wire = reply.into_bytes();
    wire.extend_from_slice(body);
    let record = send.protect(Content::Application, &wire, 0).unwrap();
    push(&mut stream, &record);
    if close {
        let alert = send.protect(Content::Alert, &[1, 0], 0).unwrap();
        push(&mut stream, &alert);
    }
    seen
}

pub(crate) fn reused(mut stream: TcpStream) -> Vec<u8> {
    let (hello, waiting, mut buffer) = speak(&mut stream);
    let (mut send, mut recv) = keys(&hello, &waiting);
    let mut seen = Vec::new();
    for last in [false, true] {
        let start = seen.len();
        loop {
            let record = pull(&mut stream, &mut buffer);
            let opened = recv.unprotect(&record).unwrap();
            if opened.content != Content::Application {
                continue;
            }
            seen.extend(opened.payload);
            if seen[start..].windows(4).any(|part| part == b"\r\n\r\n") {
                break;
            }
        }
        let body: &[u8] = if last { b"b" } else { b"a" };
        let token = if last { "close" } else { "keep-alive" };
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: {token}\r\n\r\n",
            body.len()
        );
        let mut wire = reply.into_bytes();
        wire.extend_from_slice(body);
        let record = send.protect(Content::Application, &wire, 0).unwrap();
        push(&mut stream, &record);
    }
    seen
}

pub(crate) fn local(roots: Roots) -> Client {
    let wait = Duration::from_secs(5);
    Client {
        roots,
        connect: wait,
        read: wait,
        write: wait,
        ..Client::default()
    }
}

pub(crate) fn spawn(work: fn(TcpStream) -> Vec<u8>) -> (u16, JoinHandle<Vec<u8>>) {
    begin(work)
}

pub(crate) fn begin<F>(work: F) -> (u16, JoinHandle<Vec<u8>>)
where
    F: FnOnce(TcpStream) -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        work(stream)
    });
    (port, server)
}

pub(crate) fn twice<F>(work: F) -> (u16, JoinHandle<Vec<u8>>)
where
    F: Fn(TcpStream) -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            seen.extend(work(stream));
        }
        seen
    });
    (port, server)
}

pub(crate) fn offered(peer: &mut TcpStream) -> Hello {
    let mut buffer = Vec::new();
    let first = pull(peer, &mut buffer);
    assert_eq!(first.content, Content::Handshake);
    Hello::offered(&first.fragment).unwrap()
}
