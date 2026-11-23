#[allow(dead_code)]
#[path = "contracts/tls/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "contracts/tls/sign.rs"]
mod sign;

use osistack::Client;
use osistack::http::{Method, Uri};
use osistack::socket::{Error as Socket, Phase};
use peer::{answer, frame, mint};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;
use tls::{Content, Hello, Kind, Message, Record};

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

fn speak(stream: &mut TcpStream) {
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
}

fn linger(mut stream: TcpStream) {
    speak(&mut stream);
    thread::sleep(Duration::from_millis(600));
}

fn silent() -> (u16, thread::JoinHandle<()>, osistack::Roots) {
    let held = mint("localhost");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        linger(stream);
    });
    (port, server, held.roots)
}

fn ask(client: Client, port: u16) -> Result<osistack::Response, osistack::Error> {
    let uri = Uri::parse(&format!("https://localhost:{port}/path")).unwrap();
    client.fetch(get(), &uri, b"")
}

#[test]
fn lasting() {
    let (port, server, roots) = silent();
    let client = Client {
        roots,
        total: Duration::from_millis(250),
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        write: Duration::from_secs(5),
        ..Client::default()
    };
    let outcome = ask(client, port);
    let _ = server.join();
    assert!(
        matches!(outcome, Err(osistack::Error::Timeout)),
        "{outcome:?}"
    );
}

#[test]
fn phased() {
    let (port, server, roots) = silent();
    let client = Client {
        roots,
        connect: Duration::from_secs(5),
        read: Duration::from_millis(150),
        write: Duration::from_secs(5),
        ..Client::default()
    };
    let outcome = ask(client, port);
    let _ = server.join();
    assert!(
        matches!(
            outcome,
            Err(osistack::Error::Socket(Socket::Timeout(Phase::Read)))
        ),
        "{outcome:?}"
    );
}
