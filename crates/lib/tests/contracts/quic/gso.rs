use crate::behaviour::Check;
use osistack::socket::{Datagram, Error};
use std::net::SocketAddr;
use std::time::Duration;

const LIMIT: Duration = Duration::from_secs(5);
const SIZE: usize = 64;

struct Ends {
    left: Datagram,
    right: Datagram,
    to: SocketAddr,
}

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("gso", segments as Check)]
}

fn bind() -> Ends {
    let left = Datagram::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let right = Datagram::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let to = right.local().unwrap();
    Ends { left, right, to }
}

fn segments() {
    let ends = bind();
    match ends.left.segment(SIZE) {
        Ok(()) => {}
        Err(Error::Unsupported) => panic!("gso unsupported on this platform"),
        Err(error) => panic!("{error:?}"),
    }
    let payload = vec![0xab; SIZE * 3];
    assert_eq!(
        ends.left.send(&payload, ends.to, Some(LIMIT)).unwrap(),
        payload.len()
    );
    let mut got = Vec::new();
    for _ in 0..3 {
        let mut buf = [0u8; 256];
        let (count, _) = ends.right.recv(&mut buf, Some(LIMIT)).unwrap();
        assert_eq!(count, SIZE);
        got.extend_from_slice(&buf[..count]);
    }
    assert_eq!(got, payload);
}
