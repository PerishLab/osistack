use h1::Server;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn speak(port: u16, body: &[u8]) -> Vec<u8> {
    let mut peer = TcpStream::connect(("127.0.0.1", port)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.write_all(body).unwrap();
    let mut got = Vec::new();
    let _ = peer.read_to_end(&mut got);
    got
}

#[test]
fn replies() {
    let server = Server::replying(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".to_vec(),
    ]);
    let port = server.port;
    let got = speak(port, b"GET /path?q=1 HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
    assert_eq!(got, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(seen.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
}

#[test]
fn captures() {
    let server = Server::replying(vec![b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]);
    let port = server.port;
    let body = format!(
        "POST /path?q=1 HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\ncontent-length: 5\r\n\r\nhello"
    );
    speak(port, body.as_bytes());
    let seen = server.captured();
    assert!(seen.ends_with(b"hello"));
}

#[test]
fn holds() {
    let server = Server::holding(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb".to_vec(),
    ]);
    let mut peer = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.write_all(b"GET /one HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
        .unwrap();
    let mut first = [0u8; 40];
    let count = peer.read(&mut first).unwrap();
    assert!(first[..count].starts_with(b"HTTP/1.1 200 OK"));
    peer.write_all(b"GET /two HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
        .unwrap();
    let mut second = [0u8; 40];
    let count = peer.read(&mut second).unwrap();
    assert!(second[..count].ends_with(b"b") || second[..count].contains(&b'b'));
    drop(peer);
    let seen = String::from_utf8(server.captured()).unwrap();
    assert!(seen.contains("GET /one HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("GET /two HTTP/1.1\r\n"), "{seen}");
}
