use crate::support::*;
use tls::{Error, Offer, Reply};

#[test]
fn valid() {
    let parts = Parts::default();
    assert!(Offer::parse(&parts.offer()).is_ok());
    assert!(Reply::parse(&parts.reply()).is_ok());
}

#[test]
fn version() {
    for version in [0x0300, 0x0301, 0x0302, 0x0304, 0xfefd] {
        let parts = Parts {
            version,
            ..Parts::default()
        };
        assert_eq!(Offer::parse(&parts.offer()), Err(Error::Version));
        assert_eq!(Reply::parse(&parts.reply()), Err(Error::Version));
    }
}

#[test]
fn session() {
    let long = Parts {
        session: vec![1; 33],
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&long.offer()), Err(Error::Length));
    assert_eq!(Reply::parse(&long.reply()), Err(Error::Length));
    let edge = Parts {
        session: vec![1; 32],
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&edge.offer()).unwrap().session.len(), 32);
    assert_eq!(Reply::parse(&edge.reply()).unwrap().session.len(), 32);
}

#[test]
fn suites() {
    for suites in [Vec::new(), vec![0x13], vec![0x13, 0x01, 0x13]] {
        let parts = Parts {
            suites,
            ..Parts::default()
        };
        assert_eq!(Offer::parse(&parts.offer()), Err(Error::Suites));
    }
    let many = Parts {
        suites: hex("1301 1302 1303 c02b"),
        ..Parts::default()
    };
    let offer = Offer::parse(&many.offer()).unwrap();
    assert_eq!(offer.suites, vec![0x1301, 0x1302, 0x1303, 0xc02b]);
}

#[test]
fn compression() {
    for compression in [vec![0, 1], vec![1], vec![0, 0], Vec::new()] {
        let parts = Parts {
            compression,
            ..Parts::default()
        };
        assert_eq!(Offer::parse(&parts.offer()), Err(Error::Compression));
    }
    let parts = Parts {
        compression: vec![1],
        ..Parts::default()
    };
    assert_eq!(Reply::parse(&parts.reply()), Err(Error::Compression));
}

#[test]
fn floor() {
    for (size, offer, reply) in [(0, false, false), (2, false, true), (4, true, true)] {
        let parts = Parts {
            extensions: extension(0x0a, size),
            ..Parts::default()
        };
        assert_eq!(Offer::parse(&parts.offer()).is_ok(), offer, "{size}");
        assert_eq!(Reply::parse(&parts.reply()).is_ok(), reply, "{size}");
    }
    let empty = Parts {
        extensions: Vec::new(),
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&empty.offer()), Err(Error::Length));
    assert_eq!(Reply::parse(&empty.reply()), Err(Error::Length));
}

#[test]
fn overrun() {
    let mut inner = extension(0x0a, 4);
    inner.extend(hex("002b 0010 0102 0304"));
    let parts = Parts {
        extensions: inner,
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&parts.offer()), Err(Error::Length));
    assert_eq!(Reply::parse(&parts.reply()), Err(Error::Length));
    let mut stub = extension(0x0a, 4);
    stub.push(0);
    let parts = Parts {
        extensions: stub,
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&parts.offer()), Err(Error::Length));
    let mut cut = extension(0x0a, 4);
    cut.extend(hex("002b 00"));
    let parts = Parts {
        extensions: cut,
        ..Parts::default()
    };
    assert_eq!(Reply::parse(&parts.reply()), Err(Error::Length));
}

#[test]
fn duplicate() {
    let mut inner = extension(0x0a, 4);
    inner.extend(extension(0x2b, 1));
    inner.extend(extension(0x0a, 0));
    let parts = Parts {
        extensions: inner,
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&parts.offer()), Err(Error::Duplicate));
    assert_eq!(Reply::parse(&parts.reply()), Err(Error::Duplicate));
}

#[test]
fn trailing() {
    let parts = Parts {
        tail: vec![0],
        ..Parts::default()
    };
    assert_eq!(Offer::parse(&parts.offer()), Err(Error::Trailing));
    assert_eq!(Reply::parse(&parts.reply()), Err(Error::Trailing));
}
