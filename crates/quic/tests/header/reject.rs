use crate::support::*;
use quic::{Error, Header, Kind, Long, Negotiation, Number, Retry, Short};

fn parse(text: &str, local: usize) -> Result<Header, Error> {
    Header::parse(&hex(text), local)
}

fn number() -> Number {
    Number {
        value: 1,
        length: 1,
    }
}

fn long(kind: Kind) -> Long {
    Long {
        kind,
        dcid: Vec::new(),
        scid: Vec::new(),
        token: Vec::new(),
        length: 5,
        offset: 0,
    }
}

#[test]
fn excluded() {
    assert_eq!(parse("d0 00000001 00 00 00 01 aa", 0), Err(Error::Excluded));
}

#[test]
fn version() {
    assert_eq!(parse("c0 00000002 00 00 00 01 aa", 0), Err(Error::Version));
    assert_eq!(parse("c0 ff000020 00 00 00 01 aa", 0), Err(Error::Version));
}

#[test]
fn fixed() {
    assert_eq!(parse("80 00000001 00 00 00 01 aa", 0), Err(Error::Fixed));
    assert_eq!(parse("00 aa", 0), Err(Error::Fixed));
    assert!(parse("40 aa", 0).is_ok());
}

#[test]
fn oversize() {
    let wire = format!("c0 00000001 15 {} 00 00 01 aa", "00".repeat(21));
    assert_eq!(parse(&wire, 0), Err(Error::Length));
    let wire = format!("c0 00000001 00 15 {} 00 01 aa", "00".repeat(21));
    assert_eq!(parse(&wire, 0), Err(Error::Length));
    assert_eq!(parse("40 aa", 21), Err(Error::Length));
    let wire = format!("ff 00000001 15 {} 00 {}", "00".repeat(21), "00".repeat(16));
    assert_eq!(parse(&wire, 0), Err(Error::Length));
    let wire = format!("c0 00000001 14 {} 00 00 01 aa", "00".repeat(20));
    assert!(parse(&wire, 0).is_ok());
}

#[test]
fn size() {
    assert_eq!(parse("c0 00000001 00 00 00 00", 0), Err(Error::Length));
    let short = parse("c0 00000001 00 00 00 05 aa aa aa aa", 0);
    assert_eq!(short, Err(Error::Wire(wire::Error::Truncated)));
    assert!(parse("c0 00000001 00 00 00 05 aa aa aa aa aa", 0).is_ok());
    assert_eq!(
        parse("c0 00000001 00 00 00", 0),
        Err(Error::Wire(wire::Error::Truncated))
    );
}

#[test]
fn tag() {
    let short = format!("ff 00000001 00 00 {}", "00".repeat(15));
    assert_eq!(parse(&short, 0), Err(Error::Wire(wire::Error::Truncated)));
    let exact = format!("ff 00000001 00 00 {}", "00".repeat(16));
    assert!(parse(&exact, 0).is_ok());
}

#[test]
fn list() {
    assert_eq!(
        parse("80 00000000 00 00 00000001 aa", 0),
        Err(Error::Versions)
    );
    assert!(parse("80 00000000 00 00 00000001", 0).is_ok());
}

#[test]
fn bare() {
    assert_eq!(parse("40", 0), Err(Error::Wire(wire::Error::Truncated)));
    assert_eq!(
        parse("40 01 02", 3),
        Err(Error::Wire(wire::Error::Truncated))
    );
    assert_eq!(parse("", 0), Err(Error::Wire(wire::Error::Truncated)));
}

#[test]
fn writing() {
    let mut low = long(Kind::Initial);
    low.length = 1;
    let wide = Number {
        value: 1,
        length: 2,
    };
    assert_eq!(low.write(&wide), Err(Error::Length));
    assert!(low.write(&number()).is_ok());
    let mut token = long(Kind::Handshake);
    token.token = vec![1];
    assert_eq!(token.write(&number()), Err(Error::Token));
    let mut ids = long(Kind::Initial);
    ids.dcid = vec![0; 21];
    assert_eq!(ids.write(&number()), Err(Error::Length));
    ids.dcid = Vec::new();
    ids.scid = vec![0; 21];
    assert_eq!(ids.write(&number()), Err(Error::Length));
}

#[test]
fn ids() {
    let short = Short {
        spin: false,
        phase: false,
        dcid: vec![0; 21],
        offset: 0,
    };
    assert_eq!(short.write(&number()), Err(Error::Length));
    let retry = Retry {
        unused: 0,
        dcid: vec![0; 21],
        scid: Vec::new(),
        token: Vec::new(),
        tag: [0; 16],
    };
    assert_eq!(retry.write(), Err(Error::Length));
    let mut negotiation = Negotiation {
        unused: 0,
        dcid: vec![0; 256],
        scid: Vec::new(),
        versions: Vec::new(),
    };
    assert_eq!(negotiation.write(), Err(Error::Length));
    negotiation.dcid = vec![0; 255];
    assert!(negotiation.write().is_ok());
}

#[test]
fn numbers() {
    let high = Number {
        value: 256,
        length: 1,
    };
    let zero = Number {
        value: 1,
        length: 0,
    };
    let five = Number {
        value: 1,
        length: 5,
    };
    for bad in [high, zero, five] {
        assert_eq!(long(Kind::Initial).write(&bad), Err(Error::Number));
        let short = Short {
            spin: false,
            phase: false,
            dcid: Vec::new(),
            offset: 0,
        };
        assert_eq!(short.write(&bad), Err(Error::Number));
    }
}

#[test]
fn prefixes() {
    let mut full = hex("c300000001088394c8f03e5157080000449e00000002");
    full.resize(18 + 1182, 0);
    for cut in 0..full.len() {
        assert!(Header::parse(&full[..cut], 8).is_err(), "{cut}");
    }
    let retry = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    for cut in 0..retry.len() {
        let parsed = Header::parse(&retry[..cut], 0);
        assert_eq!(parsed.is_ok(), cut >= 31, "{cut}");
    }
}

#[test]
fn every() {
    let wires = [
        ("c1000000010008f067a5502a4262b50040750001", 0),
        ("c000000001088394c8f03e5157080000449e7b9aec34", 8),
        ("4200bff4", 0),
        ("4200bff4000000000000", 4),
        ("80 00000000 04 01020304 02 0a0b 00000001 6b3343cf", 0),
        ("e0000000010000001400", 0),
        (
            "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
            0,
        ),
    ];
    for (text, local) in wires {
        let mut data = hex(text);
        data.extend(vec![0u8; 1200]);
        for cut in 0..data.len() {
            let _ = Header::parse(&data[..cut], local);
        }
    }
}
