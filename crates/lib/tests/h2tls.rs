#[allow(dead_code)]
#[path = "contracts/tls/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "contracts/tls/sign.rs"]
mod sign;

use crypto::{Aead, Group, Hash};
use h2::{Codec, Decoder, Encoder, Frame, Header, PREFACE};
use osistack::http::{Method, Uri};
use osistack::{Client, Pool};
use peer::{Waiting, answer, frame, mint, pull, push};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use tls::{Content, Hello, Kind, Layer, Message, Place, Typed};

const SECRET: [u8; 32] = [8; 32];
const RANDOM: [u8; 32] = [5; 32];

fn get() -> Method {
    Method::new("GET").unwrap()
}

fn keys(hello: &Hello, waiting: &Waiting) -> (Layer, Layer) {
    let mut found = None;
    for item in &hello.offer().extensions {
        if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer).unwrap() {
            found = items.into_iter().next();
        }
    }
    let share = found.unwrap();
    let group = match share.group {
        0x001d => Group::X25519,
        0x0017 => Group::Secp256r1,
        _ => panic!("group"),
    };
    let secret = group.agree(&SECRET, &share.key).unwrap();
    let master = tls::Schedule::new(Hash::Sha256, &secret)
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

struct Wire<'a> {
    recv: &'a mut Layer,
    stream: &'a mut TcpStream,
    buffer: &'a mut Vec<u8>,
    seen: &'a mut Vec<u8>,
    used: &'a mut usize,
}

impl Wire<'_> {
    fn take(&mut self, codec: &Codec) -> Frame {
        loop {
            if let Some((frame, size)) = codec.decode(&self.seen[*self.used..]).unwrap() {
                *self.used += size;
                return frame;
            }
            plain(self.recv, self.stream, self.buffer, self.seen);
        }
    }

    fn preface(&mut self, codec: &Codec) {
        while self.seen.len() < PREFACE.len() {
            plain(self.recv, self.stream, self.buffer, self.seen);
        }
        assert_eq!(&self.seen[..PREFACE.len()], PREFACE);
        *self.used = PREFACE.len();
        loop {
            if let Frame::Settings { ack: false, .. } = self.take(codec) {
                return;
            }
        }
    }

    fn request(&mut self, codec: &Codec) -> (u32, Vec<u8>, Vec<u8>) {
        let (id, block, mut ended) = loop {
            if let Frame::Headers {
                stream, block, fin, ..
            } = self.take(codec)
            {
                break (stream, block, fin);
            }
        };
        let mut data = Vec::new();
        while !ended {
            if let Frame::Data {
                stream,
                data: part,
                fin,
                ..
            } = self.take(codec)
                && stream == id
            {
                data.extend(part);
                ended = fin;
            }
        }
        (id, block, data)
    }
}

fn settings(ack: bool) -> Frame {
    Frame::Settings {
        ack,
        list: Vec::new(),
    }
}

fn respond(send: &mut Layer, stream: &mut TcpStream, id: u32, body: &[u8]) {
    let block = Encoder::new(4096, true).encode(&[
        Header::new(b":status", b"200"),
        Header::new(b"content-type", b"text/plain"),
    ]);
    write(
        send,
        stream,
        &[
            Frame::Headers {
                stream: id,
                fin: false,
                complete: true,
                pad: None,
                priority: None,
                block,
            },
            Frame::Data {
                stream: id,
                fin: true,
                pad: None,
                data: body.to_vec(),
            },
        ],
    );
}

fn local() -> Client {
    client(mint("localhost").roots)
}

fn client(roots: osistack::Roots) -> Client {
    let wait = Duration::from_secs(5);
    Client {
        roots,
        connect: wait,
        read: wait,
        write: wait,
        ..Client::default()
    }
}

fn spawn<T: Send + 'static>(
    work: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> (u16, thread::JoinHandle<T>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || work(listener.accept().unwrap().0));
    (port, server)
}

type Asked = (Vec<Header>, Vec<u8>, Vec<u8>);

fn reply(mut stream: TcpStream, method: &[u8], bodies: &[&[u8]]) -> Asked {
    let (hello, waiting, mut buffer) = speak(&mut stream);
    let (mut send, mut recv) = keys(&hello, &waiting);
    let codec = Codec::default();
    let mut seen = Vec::new();
    let mut used = 0;
    let mut wire = Wire {
        recv: &mut recv,
        stream: &mut stream,
        buffer: &mut buffer,
        seen: &mut seen,
        used: &mut used,
    };
    wire.preface(&codec);
    write(&mut send, wire.stream, &[settings(false), settings(true)]);
    let mut decoder = Decoder::new(4096);
    let mut fields = Vec::new();
    let mut data = Vec::new();
    for body in bodies {
        let (id, block, part) = wire.request(&codec);
        fields = decoder.decode(&block).unwrap();
        data = part;
        assert!(
            fields.contains(&Header::new(b":method", method)),
            "{fields:?}"
        );
        respond(&mut send, wire.stream, id, body);
    }
    (fields, data, seen)
}

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
