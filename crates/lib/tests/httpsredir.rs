#[allow(dead_code)]
#[path = "contracts/tls/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "contracts/tls/sign.rs"]
mod sign;

use crypto::{Aead, Group, Hash};
use osistack::Client;
use osistack::http::{Method, Uri};
use peer::{Waiting, answer, frame, mint};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use tls::{Content, Hello, Kind, Layer, Message, Place, Record, Share, Typed};

const SECRET: [u8; 32] = [8; 32];
const RANDOM: [u8; 32] = [5; 32];

fn get() -> Method {
    Method::new("GET").unwrap()
}

fn pull(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Record {
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

fn push(stream: &mut TcpStream, record: &Record) {
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

fn agreed(hello: &Hello) -> Vec<u8> {
    let share = taken(hello);
    let group = match share.group {
        0x001d => Group::X25519,
        0x0017 => Group::Secp256r1,
        _ => panic!("group"),
    };
    group.agree(&SECRET, &share.key).unwrap()
}

fn keys(hello: &Hello, waiting: &Waiting) -> (Layer, Layer) {
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

fn speak(stream: &mut TcpStream) -> (Hello, Waiting, Vec<u8>) {
    let held = mint("localhost");
    let mut buffer = Vec::new();
    let first = pull(stream, &mut buffer);
    assert_eq!(first.content, Content::Handshake);
    let hello = Hello::offered(&first.fragment).unwrap();
    let (reply, records, waiting) = answer(&hello, &held, &SECRET, RANDOM).unwrap();
    push(
        stream,
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
        push(stream, record);
    }
    let last = pull(stream, &mut buffer);
    let spoken = waiting.open(&last).unwrap();
    waiting.check(&spoken).unwrap();
    (hello, waiting, buffer)
}

fn hear(recv: &mut Layer, stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Vec<u8> {
    let mut seen = Vec::new();
    loop {
        let record = pull(stream, buffer);
        let opened = recv.unprotect(&record).unwrap();
        if opened.content != Content::Application {
            continue;
        }
        seen.extend(opened.payload);
        if seen.windows(4).any(|part| part == b"\r\n\r\n") {
            return seen;
        }
    }
}

fn say(send: &mut Layer, stream: &mut TcpStream, head: &str, body: &[u8]) {
    let mut wire = head.as_bytes().to_vec();
    wire.extend_from_slice(body);
    let record = send.protect(Content::Application, &wire, 0).unwrap();
    push(stream, &record);
}

fn found(mut stream: TcpStream, location: String) -> Vec<u8> {
    let (hello, waiting, mut buffer) = speak(&mut stream);
    let (mut send, mut recv) = keys(&hello, &waiting);
    let seen = hear(&mut recv, &mut stream, &mut buffer);
    let head = format!("HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n");
    say(&mut send, &mut stream, &head, b"");
    seen
}

fn landed(mut stream: TcpStream) -> Vec<u8> {
    let (hello, waiting, mut buffer) = speak(&mut stream);
    let (mut send, mut recv) = keys(&hello, &waiting);
    let seen = hear(&mut recv, &mut stream, &mut buffer);
    let body = b"end";
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    say(&mut send, &mut stream, &head, body);
    seen
}

#[test]
fn hopping() {
    let held = mint("localhost");
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let src = first.local_addr().unwrap().port();
    let dst = second.local_addr().unwrap().port();
    let location = format!("https://localhost:{dst}/dest");
    let origin = thread::spawn(move || {
        let (stream, _) = first.accept().unwrap();
        found(stream, location)
    });
    let target = thread::spawn(move || {
        let (stream, _) = second.accept().unwrap();
        landed(stream)
    });
    let client = Client {
        roots: held.roots,
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        write: Duration::from_secs(5),
        ..Client::default()
    };
    let uri = Uri::parse(&format!("https://localhost:{src}/from")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"end");
    let from = String::from_utf8(origin.join().unwrap()).unwrap();
    let to = String::from_utf8(target.join().unwrap()).unwrap();
    assert!(from.starts_with("GET /from HTTP/1.1\r\n"), "{from}");
    assert!(to.starts_with("GET /dest HTTP/1.1\r\n"), "{to}");
}
