use super::peer::{answer, frame, mint};
use crypto::{Aead, Group, Hash};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use tls::{Content, Hello, Kind, Layer, Message, Record, Share};

const HOST: &str = "example.test";
const CLIENT: [u8; 32] = [9; 32];
const SERVER: [u8; 32] = [8; 32];

fn share() -> Share {
    Share {
        group: 0x001d,
        key: Group::X25519.public(&CLIENT).unwrap(),
    }
}

fn hello() -> Hello {
    Hello::start(HOST.as_bytes(), &[b"h2".to_vec()], share(), [7u8; 32]).unwrap()
}

fn shared() -> Vec<u8> {
    Group::X25519
        .agree(&CLIENT, &Group::X25519.public(&SERVER).unwrap())
        .unwrap()
}

fn handshake() {
    let held = mint(HOST);
    let hello = hello();
    let (reply, records, waiting) = answer(&hello, &held, &SERVER, [5u8; 32]).unwrap();
    let accepted = hello.accept(&reply, &shared()).unwrap();
    let verified = accepted
        .verify(HOST, &held.roots, held.now, &records)
        .unwrap();
    let complete = verified.finish().unwrap();
    waiting.check(complete.spoken()).unwrap();
    let master = tls::Schedule::new(Hash::Sha256, &shared())
        .unwrap()
        .master()
        .unwrap();
    let through = waiting.digest();
    assert_eq!(through, verified.digest());
    assert_eq!(
        complete.client().secret(),
        master.client(&through).unwrap().secret()
    );
    assert_eq!(
        complete.server().secret(),
        master.server(&through).unwrap().secret()
    );
    let ping = complete.client().keys(Aead::Aes128).unwrap();
    let pong = master.client(&through).unwrap().keys(Aead::Aes128).unwrap();
    assert_eq!(ping, pong);
}

fn pull(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Record {
    let mut chunk = [0u8; 2048];
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

fn remote() {
    let held = mint(HOST);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = Vec::new();
        let first = pull(&mut stream, &mut buffer);
        assert_eq!(first.content, Content::Handshake);
        let hello = Hello::offered(&first.fragment).unwrap();
        let (reply, records, waiting) = answer(&hello, &held, &SERVER, [5u8; 32]).unwrap();
        push(
            &mut stream,
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
            push(&mut stream, record);
        }
        let last = pull(&mut stream, &mut buffer);
        let spoken = waiting.open(&last).unwrap();
        waiting.check(&spoken).unwrap();
    });
    let mut stream = TcpStream::connect(addr).unwrap();
    let hello = hello();
    push(
        &mut stream,
        &frame(Content::Handshake, hello.spoken().to_vec()),
    );
    let mut buffer = Vec::new();
    let second = pull(&mut stream, &mut buffer);
    let (message, used) = Message::parse(&second.fragment, 1 << 16).unwrap().unwrap();
    assert_eq!(used, second.fragment.len());
    assert_eq!(message.kind, Kind::Reply);
    let reply = tls::Reply::parse(&message.body).unwrap();
    let accepted = hello.accept(&reply, &shared()).unwrap();
    let flight = pull(&mut stream, &mut buffer);
    let verified = accepted
        .verify(HOST, &mint(HOST).roots, mint(HOST).now, &[flight])
        .unwrap();
    let complete = verified.finish().unwrap();
    let keys = accepted.client().keys(Aead::Aes128).unwrap();
    let record = Layer::new(Aead::Aes128, &keys)
        .unwrap()
        .protect(Content::Handshake, complete.spoken(), 0)
        .unwrap();
    push(&mut stream, &record);
    server.join().unwrap();
    assert_eq!(complete.digest().len(), 32);
}

#[test]
fn piped() {
    handshake();
}

#[test]
fn loopback() {
    remote();
}
