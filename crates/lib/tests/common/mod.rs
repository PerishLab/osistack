use osistack::{Client, http::Uri};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Server {
    pub uri: Uri,
    pub port: u16,
    handle: JoinHandle<Vec<u8>>,
}

impl Server {
    pub fn replying(parts: Vec<Vec<u8>>) -> Self {
        Self::start(parts, Duration::ZERO, Duration::ZERO)
    }

    pub fn pausing(parts: Vec<Vec<u8>>, gap: Duration) -> Self {
        Self::start(parts, gap, Duration::ZERO)
    }

    pub fn silent(hold: Duration) -> Self {
        Self::start(Vec::new(), Duration::ZERO, hold)
    }

    pub fn captured(self) -> Vec<u8> {
        self.handle.join().unwrap()
    }

    fn start(parts: Vec<Vec<u8>>, gap: Duration, hold: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let uri = Uri::parse(&format!("http://127.0.0.1:{port}/path?q=1")).unwrap();
        let handle = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            let seen = Self::request(&mut peer);
            for part in parts {
                if peer.write_all(&part).is_err() {
                    break;
                }
                thread::sleep(gap);
            }
            thread::sleep(hold);
            seen
        });
        Self { uri, port, handle }
    }

    fn request(peer: &mut std::net::TcpStream) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        let mut needed = None;
        loop {
            let count = peer.read(&mut buf).unwrap_or(0);
            seen.extend_from_slice(&buf[..count]);
            let split = seen.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(at) = split {
                let text = String::from_utf8_lossy(&seen[..at]).to_ascii_lowercase();
                let length = text
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok());
                needed = Some(at + 4 + length.unwrap_or(0));
            }
            if count == 0 || needed.is_some_and(|total| seen.len() >= total) {
                return seen;
            }
        }
    }
}

pub fn client() -> Client {
    Client {
        connect: Duration::from_secs(5),
        read: Duration::from_secs(5),
        write: Duration::from_secs(5),
        ..Client::default()
    }
}

pub fn text(parts: &[&str]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.as_bytes().to_vec()).collect()
}
