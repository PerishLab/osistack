use http::Uri;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Server {
    pub uri: Uri,
    pub port: u16,
    handle: JoinHandle<io::Result<Vec<u8>>>,
}

impl Server {
    pub fn replying(parts: Vec<Vec<u8>>) -> io::Result<Self> {
        Self::start(parts, Duration::ZERO, Duration::ZERO)
    }

    pub fn pausing(parts: Vec<Vec<u8>>, gap: Duration) -> io::Result<Self> {
        Self::start(parts, gap, Duration::ZERO)
    }

    pub fn silent(hold: Duration) -> io::Result<Self> {
        Self::start(Vec::new(), Duration::ZERO, hold)
    }

    pub fn holding(parts: Vec<Vec<u8>>) -> io::Result<Self> {
        let (listener, port, uri) = bound()?;
        let handle = thread::spawn(move || -> io::Result<Vec<u8>> {
            let (mut peer, _) = listener.accept()?;
            let mut seen = Vec::new();
            for part in parts {
                seen.extend(take(&mut peer));
                if peer.write_all(&part).is_err() {
                    break;
                }
            }
            Ok(seen)
        });
        Ok(Self { uri, port, handle })
    }

    pub fn captured(self) -> io::Result<Vec<u8>> {
        self.handle.join().map_err(|_| io::Error::other("thread"))?
    }

    fn start(parts: Vec<Vec<u8>>, gap: Duration, hold: Duration) -> io::Result<Self> {
        let (listener, port, uri) = bound()?;
        let handle = thread::spawn(move || -> io::Result<Vec<u8>> {
            let (mut peer, _) = listener.accept()?;
            let seen = take(&mut peer);
            for part in parts {
                if peer.write_all(&part).is_err() {
                    break;
                }
                thread::sleep(gap);
            }
            thread::sleep(hold);
            Ok(seen)
        });
        Ok(Self { uri, port, handle })
    }
}

fn bound() -> io::Result<(TcpListener, u16, Uri)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let uri = Uri::parse(&format!("http://127.0.0.1:{port}/path?q=1")).map_err(fault)?;
    Ok((listener, port, uri))
}

fn fault(error: http::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

fn take(peer: &mut TcpStream) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    let mut needed = None;
    loop {
        let count = peer.read(&mut buf).unwrap_or(0);
        seen.extend_from_slice(&buf[..count]);
        let split = seen.windows(4).position(|window| window == b"\r\n\r\n");
        if let Some(at) = split {
            needed = Some(at + 4 + length(&seen[..at]));
        }
        if count == 0 || needed.is_some_and(|total| seen.len() >= total) {
            return seen;
        }
    }
}

fn length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    text.lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}
