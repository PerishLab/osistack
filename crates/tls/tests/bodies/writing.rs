use crate::support::*;
use tls::{Chain, Encrypted, Entry, Error, Request, Ticket, Verify};

fn entry(size: usize) -> Entry {
    Entry {
        cert: vec![7; size],
        extensions: vec![],
    }
}

fn chain(context: usize, entries: Vec<Entry>) -> Chain {
    Chain {
        context: vec![1; context],
        entries,
    }
}

fn ticket(lifetime: u32, nonce: usize, size: usize) -> Ticket {
    Ticket {
        lifetime,
        add: 1,
        nonce: vec![2; nonce],
        ticket: vec![3; size],
        extensions: vec![],
    }
}

#[test]
fn chains() {
    assert_eq!(chain(256, vec![entry(1)]).write(), Err(Error::Length));
    assert!(chain(255, vec![entry(1)]).write().is_ok());
    assert_eq!(chain(0, vec![entry(0)]).write(), Err(Error::Length));
    let dup = vec![extension(1, &[]), extension(1, &[])];
    let both = Entry {
        cert: vec![1],
        extensions: dup,
    };
    assert_eq!(chain(0, vec![both]).write(), Err(Error::Duplicate));
}

#[test]
fn lists() {
    let fits = chain(0, vec![entry((1 << 24) - 1 - 5)]);
    let bytes = fits.write().unwrap();
    assert_eq!(bytes.len(), 4 + (1 << 24) - 1);
    assert_eq!(Chain::parse(&bytes).unwrap(), fits);
    assert_eq!(chain(0, vec![entry(1 << 24)]).write(), Err(Error::Length));
    assert_eq!(
        chain(0, vec![entry((1 << 24) - 5)]).write(),
        Err(Error::Length)
    );
    let halves = vec![entry(9_000_000), entry(9_000_000)];
    assert_eq!(chain(0, halves).write(), Err(Error::Length));
}

#[test]
fn requests() {
    let bare = Request {
        context: vec![],
        extensions: vec![],
    };
    assert_eq!(bare.write(), Err(Error::Missing));
    let other = Request {
        context: vec![],
        extensions: vec![extension(1, &[])],
    };
    assert_eq!(other.write(), Err(Error::Missing));
    let long = Request {
        context: vec![0; 256],
        extensions: vec![extension(13, &[0, 2, 4, 3])],
    };
    assert_eq!(long.write(), Err(Error::Length));
    let good = Request {
        context: vec![0; 255],
        extensions: vec![extension(13, &[0, 2, 4, 3])],
    };
    assert_eq!(Request::parse(&good.write().unwrap()).unwrap(), good);
}

#[test]
fn tickets() {
    assert!(ticket(604_800, 0, 1).write().is_ok());
    assert_eq!(ticket(604_801, 0, 1).write(), Err(Error::Value));
    assert_eq!(ticket(1, 0, 0).write(), Err(Error::Length));
    assert_eq!(ticket(1, 256, 1).write(), Err(Error::Length));
    assert_eq!(
        ticket(1, 255, 1).write().unwrap().len(),
        4 + 4 + 1 + 255 + 2 + 1 + 2
    );
    assert_eq!(ticket(1, 0, 65536).write(), Err(Error::Length));
    let full = ticket(1, 0, 65535);
    assert_eq!(Ticket::parse(&full.write().unwrap()).unwrap(), full);
}

#[test]
fn signatures() {
    let wide = Verify {
        algorithm: 1,
        signature: vec![0; 65536],
    };
    assert_eq!(wide.write(), Err(Error::Length));
    let full = Verify {
        algorithm: 1,
        signature: vec![0; 65535],
    };
    assert_eq!(Verify::parse(&full.write().unwrap()).unwrap(), full);
}

#[test]
fn extensions() {
    let dup = Encrypted {
        extensions: vec![extension(5, &[]), extension(5, &[1])],
    };
    assert_eq!(dup.write(), Err(Error::Duplicate));
    let wide = Encrypted {
        extensions: vec![extension(5, &vec![0; 65536])],
    };
    assert_eq!(wide.write(), Err(Error::Length));
    let ok = Encrypted {
        extensions: vec![extension(5, &vec![0; 65531])],
    };
    assert_eq!(Encrypted::parse(&ok.write().unwrap()).unwrap(), ok);
}
