use crate::behaviour::Check;
use osistack::socket::{Datagram, Mark};
use std::net::SocketAddr;
use std::time::Duration;

const LIMIT: Duration = Duration::from_secs(5);

struct Ends {
    left: Datagram,
    right: Datagram,
    from: SocketAddr,
    to: SocketAddr,
}

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("ecn", marks as Check)]
}

fn bind() -> Ends {
    let left = Datagram::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let right = Datagram::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let from = left.local().unwrap();
    let to = right.local().unwrap();
    Ends {
        left,
        right,
        from,
        to,
    }
}

fn marks() {
    let ends = bind();
    ends.right.observe(true).unwrap();
    for mark in [Mark::Plain, Mark::Ect0, Mark::Ect1, Mark::Ce] {
        ends.left.mark(mark).unwrap();
        assert_eq!(ends.left.coded().unwrap(), mark, "{mark:?}");
        assert_eq!(ends.left.send(b"ecn", ends.to, Some(LIMIT)).unwrap(), 3);
        let mut buf = [0u8; 8];
        let (count, peer, got) = ends.right.marked(&mut buf, Some(LIMIT)).unwrap();
        assert_eq!(&buf[..count], b"ecn");
        assert_eq!(peer, ends.from);
        assert_eq!(got, mark, "{mark:?}");
    }
}
