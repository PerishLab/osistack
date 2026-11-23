pub mod httpd;
pub mod outside;

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

pub fn certs(der: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = String::new();
    let mut data = der.to_vec();
    let pad = (3 - data.len() % 3) % 3;
    data.extend(std::iter::repeat_n(0, pad));
    for chunk in data.chunks(3) {
        let n = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        body.push(T[((n >> 18) & 63) as usize] as char);
        body.push(T[((n >> 12) & 63) as usize] as char);
        body.push(T[((n >> 6) & 63) as usize] as char);
        body.push(T[(n & 63) as usize] as char);
    }
    if pad > 0 {
        body.truncate(body.len() - pad);
        body.extend(std::iter::repeat_n('=', pad));
    }
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}
