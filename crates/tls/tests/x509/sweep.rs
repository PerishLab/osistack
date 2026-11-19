use crate::data::{CA, P384, P521, RFCEC, RFCRSA, RSA};
use crate::support::{Dice, hex, load, tlv};
use tls::x509::{Certificate, Der, Flaw, Oid, Time};

const ALL: [&str; 6] = [RFCRSA, RFCEC, RSA, CA, P384, P521];

#[test]
fn prefixes() {
    for text in ALL {
        let wire = hex(text);
        for size in 0..wire.len() {
            assert!(Certificate::parse(&wire[..size]).is_err(), "{size}");
        }
        assert!(Certificate::parse(&wire).is_ok());
    }
}

#[test]
fn appended() {
    for text in ALL {
        let wire = hex(text);
        for extra in [0x00, 0x30, 0xff] {
            let mut more = wire.clone();
            more.push(extra);
            assert_eq!(Certificate::parse(&more).unwrap_err(), Flaw::Trailing);
        }
        let mut pair = wire.clone();
        pair.extend(&wire);
        assert_eq!(Certificate::parse(&pair).unwrap_err(), Flaw::Trailing);
    }
}

fn tally(wire: &[u8]) -> (usize, usize) {
    let mut counts = (0, 0);
    for index in 0..wire.len() * 8 {
        let mut bent = wire.to_vec();
        bent[index / 8] ^= 1 << (index % 8);
        match Certificate::parse(&bent) {
            Ok(_) => counts.0 += 1,
            Err(_) => counts.1 += 1,
        }
    }
    counts
}

#[test]
fn flips() {
    let mut passed = 0;
    let mut failed = 0;
    for text in ALL {
        let counts = tally(&hex(text));
        passed += counts.0;
        failed += counts.1;
    }
    assert_eq!(passed + failed, 2830 * 8);
    assert!(passed > 1000 && failed > 1000, "{passed} {failed}");
}

#[test]
fn signed() {
    for text in ALL {
        let (wire, cert) = load(text);
        let mut bent = wire.clone();
        let last = bent.len() - 1;
        bent[last] ^= 1;
        let other = Certificate::parse(&bent).unwrap();
        assert_ne!(other.signature, cert.signature);
        assert_eq!(other.tbs, cert.tbs);
        assert_eq!(other.key, cert.key);
        bent[0] ^= 1;
        assert!(Certificate::parse(&bent).is_err());
    }
}

#[test]
fn bent() {
    let mut dice = Dice::new(7);
    for text in ALL {
        let wire = hex(text);
        for _ in 0..400 {
            let mut bent = wire.clone();
            for _ in 0..1 + dice.below(4) {
                let at = dice.below(bent.len());
                bent[at] = dice.next() as u8;
            }
            let _ = Certificate::parse(&bent);
        }
    }
}

#[test]
fn spliced() {
    let mut dice = Dice::new(11);
    for text in ALL {
        let wire = hex(text);
        for _ in 0..200 {
            let from = dice.below(wire.len());
            let to = from + dice.below(wire.len() - from);
            let mut cut = wire.clone();
            cut.drain(from..to);
            let _ = Certificate::parse(&cut);
            let mut grown = wire.clone();
            let count = 1 + dice.below(8);
            let junk = dice.bytes(count);
            grown.splice(from..from, junk);
            assert!(Certificate::parse(&grown).is_err());
        }
    }
}

#[test]
fn random() {
    let mut dice = Dice::new(3);
    for _ in 0..2000 {
        let size = dice.below(400);
        let wire = dice.bytes(size);
        assert!(Certificate::parse(&wire).is_err());
        let framed = tlv(0x30, &wire);
        assert!(Certificate::parse(&framed).is_err());
    }
}

#[test]
fn pieces() {
    let mut dice = Dice::new(5);
    for _ in 0..3000 {
        let size = dice.below(40);
        let wire = dice.bytes(size);
        let mut der = Der::new(&wire);
        while !der.done() && der.read().is_ok() {}
        let _ = Oid::parse(&wire);
        let _ = Time::parse(0x17, &wire);
        let _ = Time::parse(0x18, &wire);
        let _ = tls::x509::integer(&wire);
        let _ = tls::x509::unsigned(&wire);
        let _ = tls::x509::boolean(&wire);
        let _ = tls::x509::bits(&wire);
        if let Ok(oid) = Oid::parse(&wire) {
            assert_eq!(Oid::from(&oid.arcs()).bytes(), oid.bytes());
            assert!(!oid.to_string().is_empty());
        }
    }
}

#[test]
fn clocks() {
    let mut dice = Dice::new(9);
    for _ in 0..3000 {
        let text: Vec<u8> = (0..13).map(|_| b'0' + dice.below(10) as u8).collect();
        let mut text = text;
        text[12] = b'Z';
        if let Ok(time) = Time::parse(0x17, &text) {
            let again = Time::parse(
                0x17,
                format!(
                    "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                    time.year % 100,
                    time.month,
                    time.day,
                    time.hour,
                    time.minute,
                    time.second
                )
                .as_bytes(),
            );
            assert_eq!(again, Ok(time));
        }
    }
}
