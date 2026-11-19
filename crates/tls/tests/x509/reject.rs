use crate::support::{
    COMMON, ECDSA256, Parts, RSA256, alg, extension, flaw, int, oid, seq, tlv, utc, when, wrap,
};
use tls::x509::{Certificate, Flaw};

fn versioned(number: &[u8]) -> Parts {
    Parts {
        version: tlv(0xa0, &int(number)),
        ..Parts::base()
    }
}

#[test]
fn baseline() {
    let cert = Parts::base().parse().unwrap();
    assert_eq!((cert.version, cert.serial.as_slice()), (3, &[1][..]));
    assert_eq!(cert.from, when((2026, 1, 1), (0, 0, 0)));
    assert_eq!(cert.until, when((2030, 1, 1), (0, 0, 0)));
    assert_eq!(cert.issuer.text(&parsed(COMMON)), Some("ca".into()));
    assert_eq!(cert.subject.text(&parsed(COMMON)), Some("leaf".into()));
    assert_eq!(cert.signature, [1, 2, 3, 4]);
    assert!(cert.extensions.is_empty());
}

fn parsed(bytes: &[u8]) -> tls::x509::Oid {
    tls::x509::Oid::parse(bytes).unwrap()
}

#[test]
fn absent() {
    let parts = Parts {
        version: vec![],
        ..Parts::base()
    };
    assert_eq!(parts.parse().unwrap().version, 1);
}

#[test]
fn second() {
    let cert = versioned(&[1]).parse().unwrap();
    assert_eq!(cert.version, 2);
    let unique = Parts {
        unique: [tlv(0x81, &[0, 0xff]), tlv(0x82, &[0, 0x0f])].concat(),
        ..versioned(&[1])
    };
    assert_eq!(unique.parse().unwrap().version, 2);
}

#[test]
fn explicit() {
    assert_eq!(flaw(&versioned(&[0])), Flaw::Version);
}

#[test]
fn future() {
    assert_eq!(flaw(&versioned(&[3])), Flaw::Version);
    assert_eq!(flaw(&versioned(&[1, 0])), Flaw::Version);
    assert_eq!(flaw(&versioned(&[0x7f])), Flaw::Version);
}

#[test]
fn signed() {
    assert_eq!(flaw(&versioned(&[0xff])), Flaw::Value);
    assert_eq!(flaw(&versioned(&[0, 2])), Flaw::Minimal);
}

#[test]
fn wrapped() {
    let parts = Parts {
        version: tlv(0xa0, &[int(&[2]), int(&[2])].concat()),
        ..Parts::base()
    };
    assert_eq!(flaw(&parts), Flaw::Trailing);
    let empty = Parts {
        version: tlv(0xa0, &[]),
        ..Parts::base()
    };
    assert_eq!(flaw(&empty), Flaw::Length);
}

#[test]
fn early() {
    let unique = tlv(0x81, &[0, 0xff]);
    let first = Parts {
        version: vec![],
        unique: unique.clone(),
        ..Parts::base()
    };
    assert_eq!(flaw(&first), Flaw::Version);
    let tail = Parts {
        version: vec![],
        extensions: wrap(&[extension(&[0x2b, 6, 1], None, &[1])]),
        ..Parts::base()
    };
    assert_eq!(flaw(&tail), Flaw::Version);
    let second = Parts {
        extensions: wrap(&[extension(&[0x2b, 6, 1], None, &[1])]),
        ..versioned(&[1])
    };
    assert_eq!(flaw(&second), Flaw::Version);
    let issuer = Parts {
        unique: tlv(0x82, &[0, 1]),
        version: vec![],
        ..Parts::base()
    };
    assert_eq!(flaw(&issuer), Flaw::Version);
}

#[test]
fn unusable() {
    let parts = Parts {
        unique: tlv(0x81, &[9, 0]),
        ..Parts::base()
    };
    assert_eq!(flaw(&parts), Flaw::Value);
    let empty = Parts {
        unique: tlv(0x82, &[]),
        ..Parts::base()
    };
    assert_eq!(flaw(&empty), Flaw::Value);
}

#[test]
fn serials() {
    let with = |serial: Vec<u8>| Parts {
        serial,
        ..Parts::base()
    };
    assert_eq!(flaw(&with(int(&[]))), Flaw::Value);
    assert_eq!(flaw(&with(int(&[0, 1]))), Flaw::Minimal);
    assert_eq!(flaw(&with(oid(&[1]))), Flaw::Tag);
    assert_eq!(with(int(&[0x80])).parse().unwrap().serial, [0x80]);
    assert_eq!(with(int(&[0])).parse().unwrap().serial, [0]);
    let long = vec![0x41; 40];
    assert_eq!(with(int(&long)).parse().unwrap().serial, long);
}

#[test]
fn mismatch() {
    let other = Parts {
        outer: alg(RSA256, Some(&[5, 0])),
        ..Parts::base()
    };
    assert_eq!(flaw(&other), Flaw::Mismatch);
    let params = Parts {
        outer: alg(ECDSA256, Some(&[5, 0])),
        ..Parts::base()
    };
    assert_eq!(flaw(&params), Flaw::Mismatch);
    let inner = Parts {
        algorithm: alg(RSA256, Some(&[5, 0])),
        ..Parts::base()
    };
    assert_eq!(flaw(&inner), Flaw::Mismatch);
    let same = Parts {
        algorithm: alg(RSA256, Some(&[5, 0])),
        outer: alg(RSA256, Some(&[5, 0])),
        ..Parts::base()
    };
    assert!(same.parse().is_ok());
}

#[test]
fn padding() {
    let parts = Parts {
        signature: tlv(3, &[1, 0x02]),
        ..Parts::base()
    };
    assert_eq!(flaw(&parts), Flaw::Value);
    let empty = Parts {
        signature: tlv(3, &[0]),
        ..Parts::base()
    };
    assert_eq!(empty.parse().unwrap().signature, Vec::<u8>::new());
    let bare = Parts {
        signature: tlv(3, &[]),
        ..Parts::base()
    };
    assert_eq!(flaw(&bare), Flaw::Value);
    let kind = Parts {
        signature: tlv(4, &[0, 1]),
        ..Parts::base()
    };
    assert_eq!(flaw(&kind), Flaw::Tag);
}

#[test]
fn framing() {
    let parts = Parts::base();
    let good = parts.build();
    let mut more = good.clone();
    more.push(0);
    assert_eq!(Certificate::parse(&more).unwrap_err(), Flaw::Trailing);
    let tbs = seq(&[
        &parts.version,
        &parts.serial,
        &parts.algorithm,
        &parts.issuer,
        &parts.validity,
        &parts.subject,
        &parts.spki,
    ]);
    assert_eq!(
        Certificate::parse(&seq(&[&tbs, &parts.outer])).unwrap_err(),
        Flaw::Length
    );
    let extra = seq(&[&tbs, &parts.outer, &parts.signature, &[5, 0]]);
    assert_eq!(Certificate::parse(&extra).unwrap_err(), Flaw::Trailing);
    assert_eq!(
        Certificate::parse(&tlv(0x31, &good[2..])).unwrap_err(),
        Flaw::Tag
    );
    assert_eq!(Certificate::parse(&[]).unwrap_err(), Flaw::Length);
    let wrong = seq(&[&tlv(4, &tbs), &parts.outer, &parts.signature]);
    assert_eq!(Certificate::parse(&wrong).unwrap_err(), Flaw::Tag);
}

#[test]
fn body() {
    let parts = Parts::base();
    let cut = |keep: usize| {
        let all: [&[u8]; 6] = [
            &parts.serial,
            &parts.algorithm,
            &parts.issuer,
            &parts.validity,
            &parts.subject,
            &parts.spki,
        ];
        let tbs = seq(&all[..keep]);
        Certificate::parse(&seq(&[&tbs, &parts.outer, &parts.signature])).unwrap_err()
    };
    for keep in 0..6 {
        assert!(matches!(cut(keep), Flaw::Length | Flaw::Tag), "{keep}");
    }
    let extra = seq(&[
        &parts.serial,
        &parts.algorithm,
        &parts.issuer,
        &parts.validity,
        &parts.subject,
        &parts.spki,
        &[5, 0],
    ]);
    let whole = seq(&[&extra, &parts.outer, &parts.signature]);
    assert_eq!(Certificate::parse(&whole).unwrap_err(), Flaw::Trailing);
}

#[test]
fn dates() {
    let with = |validity: Vec<u8>| Parts {
        validity,
        ..Parts::base()
    };
    let good = utc("260101000000Z");
    let bad = utc("261301000000Z");
    assert_eq!(flaw(&with(seq(&[&good, &bad]))), Flaw::Time);
    assert_eq!(flaw(&with(seq(&[&bad, &good]))), Flaw::Time);
    assert_eq!(flaw(&with(seq(&[&good]))), Flaw::Length);
    assert_eq!(flaw(&with(seq(&[&good, &good, &good]))), Flaw::Trailing);
    assert_eq!(flaw(&with(seq(&[&good, &tlv(0x0c, b"x")]))), Flaw::Tag);
    assert_eq!(flaw(&with(tlv(0x31, &good))), Flaw::Tag);
    let general = tlv(0x18, b"20400101000000Z");
    assert!(with(seq(&[&good, &general])).parse().is_ok());
    let late = utc("300101000000Z");
    assert!(with(seq(&[&late, &good])).parse().is_ok());
}

#[test]
fn tbstag() {
    let parts = Parts::base();
    let inner = [
        &parts.version[..],
        &parts.serial,
        &parts.algorithm,
        &parts.issuer,
        &parts.validity,
        &parts.subject,
        &parts.spki,
    ]
    .concat();
    let good = seq(&[&seq(&[&inner]), &parts.outer, &parts.signature]);
    assert!(Certificate::parse(&good).is_ok());
    let bad = seq(&[&tlv(0x31, &inner), &parts.outer, &parts.signature]);
    assert_eq!(Certificate::parse(&bad).unwrap_err(), Flaw::Tag);
}
