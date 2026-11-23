use osistack::Client;
use std::time::Duration;

pub use osistack::h1::Server;

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
