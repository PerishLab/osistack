#[allow(dead_code)]
#[path = "contracts/tls/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "contracts/tls/sign.rs"]
mod sign;

use crypto::{Aead, Group, Hash};
use h2::{Codec, Decoder, Encoder, Frame, Header, PREFACE};
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
    let mut held = mint("localhost");
    held.protocol = Some(b"h2".to_vec());
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

fn plain(recv: &mut Layer, stream: &mut TcpStream, buffer: &mut Vec<u8>, seen: &mut Vec<u8>) {
    loop {
        let record = pull(stream, buffer);
        let opened = recv.unprotect(&record).unwrap();
        if opened.content != Content::Application {
            continue;
        }
        seen.extend(opened.payload);
        return;
    }
}

fn write(send: &mut Layer, stream: &mut TcpStream, frames: &[Frame]) {
    let codec = Codec::default();
    let mut wire = Vec::new();
    for frame in frames {
        wire.extend(codec.encode(frame).unwrap());
    }
    let record = send.protect(Content::Application, &wire, 0).unwrap();
    push(stream, &record);
}

fn next(codec: &Codec, seen: &[u8], used: &mut usize) -> Option<Frame> {
    let (frame, size) = codec.decode(&seen[*used..]).unwrap()?;
    *used += size;
    Some(frame)
}

fn serve(mut stream: TcpStream) -> Vec<u8> {
    let (hello, waiting, mut buffer) = speak(&mut stream);
    let (mut send, mut recv) = keys(&hello, &waiting);
    let codec = Codec::default();
    let mut seen = Vec::new();
    while seen.len() < PREFACE.len() {
        plain(&mut recv, &mut stream, &mut buffer, &mut seen);
    }
    assert_eq!(&seen[..PREFACE.len()], PREFACE);
    let mut used = PREFACE.len();
    let mut settings = None;
    while settings.is_none() {
        if let Some(frame) = next(&codec, &seen, &mut used) {
            if let Frame::Settings { ack: false, .. } = frame {
                settings = Some(frame);
            }
            continue;
        }
        plain(&mut recv, &mut stream, &mut buffer, &mut seen);
    }
    write(
        &mut send,
        &mut stream,
        &[
            Frame::Settings {
                ack: false,
                list: Vec::new(),
            },
            Frame::Settings {
                ack: true,
                list: Vec::new(),
            },
        ],
    );
    let mut headers = None;
    while headers.is_none() {
        if let Some(frame) = next(&codec, &seen, &mut used) {
            if let Frame::Headers { stream, block, .. } = frame {
                headers = Some((stream, block));
            }
            continue;
        }
        plain(&mut recv, &mut stream, &mut buffer, &mut seen);
    }
    let (id, block) = headers.unwrap();
    let fields = Decoder::new(4096).decode(&block).unwrap();
    assert!(
        fields.contains(&Header::new(b":method", b"GET")),
        "{fields:?}"
    );
    let reply = Encoder::new(4096, true).encode(&[
        Header::new(b":status", b"200"),
        Header::new(b"content-type", b"text/plain"),
    ]);
    write(
        &mut send,
        &mut stream,
        &[
            Frame::Headers {
                stream: id,
                fin: false,
                complete: true,
                pad: None,
                priority: None,
                block: reply,
            },
            Frame::Data {
                stream: id,
                fin: true,
                pad: None,
                data: b"ok".to_vec(),
            },
        ],
    );
    seen
}

#[test]
fn fetch() {
    let held = mint("localhost");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        serve(stream)
    });
    let client = Client {
        roots: held.roots,
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        write: Duration::from_secs(5),
        ..Client::default()
    };
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    let response = client.fetch(get(), &uri, b"").unwrap();
    assert_eq!(response.head.status.get(), 200);
    assert_eq!(response.body, b"ok");
    let seen = server.join().unwrap();
    assert!(seen.starts_with(PREFACE), "{seen:?}");
}
