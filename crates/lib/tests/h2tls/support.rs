#[allow(dead_code)]
#[path = "../contracts/tls/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "../contracts/tls/sign.rs"]
mod sign;

use crypto::{Aead, Group, Hash};
pub(crate) use h2::{Codec, Decoder, Encoder, Frame, Header, PREFACE, Setting};
use osistack::Client;
use osistack::http::Method;
use peer::{Waiting, answer, frame, mint, pull, push};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use tls::{Content, Hello, Kind, Layer, Message, Place, Typed};

pub(crate) const SECRET: [u8; 32] = [8; 32];
pub(crate) const RANDOM: [u8; 32] = [5; 32];

pub(crate) fn get() -> Method {
    Method::new("GET").unwrap()
}

pub(crate) fn keys(hello: &Hello, waiting: &Waiting) -> (Layer, Layer) {
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

pub(crate) fn speak(stream: &mut TcpStream) -> (Hello, Waiting, Vec<u8>) {
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

pub(crate) fn plain(
    recv: &mut Layer,
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    seen: &mut Vec<u8>,
) {
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

pub(crate) fn write(send: &mut Layer, stream: &mut TcpStream, frames: &[Frame]) {
    let codec = Codec::default();
    let mut wire = Vec::new();
    for frame in frames {
        wire.extend(codec.encode(frame).unwrap());
    }
    let record = send.protect(Content::Application, &wire, 0).unwrap();
    push(stream, &record);
}

pub(crate) struct Wire<'a> {
    pub(crate) recv: &'a mut Layer,
    pub(crate) stream: &'a mut TcpStream,
    pub(crate) buffer: &'a mut Vec<u8>,
    pub(crate) seen: &'a mut Vec<u8>,
    pub(crate) used: &'a mut usize,
}

impl Wire<'_> {
    pub(crate) fn take(&mut self, codec: &Codec) -> Frame {
        loop {
            if let Some((frame, size)) = codec.decode(&self.seen[*self.used..]).unwrap() {
                *self.used += size;
                return frame;
            }
            plain(self.recv, self.stream, self.buffer, self.seen);
        }
    }

    pub(crate) fn preface(&mut self, codec: &Codec) {
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

    pub(crate) fn request(&mut self, codec: &Codec) -> (u32, Vec<u8>, Vec<u8>) {
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

pub(crate) fn settings(ack: bool) -> Frame {
    Frame::Settings {
        ack,
        list: Vec::new(),
    }
}

pub(crate) fn respond(send: &mut Layer, stream: &mut TcpStream, id: u32, body: &[u8]) {
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

pub(crate) fn local() -> Client {
    client(mint("localhost").roots)
}

pub(crate) fn client(roots: osistack::Roots) -> Client {
    let wait = Duration::from_secs(5);
    Client {
        roots,
        connect: wait,
        read: wait,
        write: wait,
        ..Client::default()
    }
}

pub(crate) fn spawn<T: Send + 'static>(
    work: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> (u16, thread::JoinHandle<T>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || work(listener.accept().unwrap().0));
    (port, server)
}

pub(crate) type Asked = (Vec<Header>, Vec<u8>, Vec<u8>);

pub(crate) fn reply(mut stream: TcpStream, method: &[u8], bodies: &[&[u8]]) -> Asked {
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
