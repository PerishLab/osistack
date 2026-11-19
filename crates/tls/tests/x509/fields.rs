use crate::data::{CA, P384, P521, RFCEC, RFCRSA, RSA};
use crate::support::{
    BASIC, COMMON, ECDSA256, P256, Parts, RSA256, alg, extension, flaw, hex, int, oid, point,
    rewrite, seq, single, spki, tlv, wrap,
};
use tls::x509::{Algorithm, Certificate, Flaw, Name, Public, Scheme};

#[test]
fn names() {
    let with = |issuer: Vec<u8>| Parts {
        issuer,
        ..Parts::base()
    };
    let pair = seq(&[&oid(COMMON), &tlv(0x0c, b"a")]);
    let other = seq(&[&oid(&[0x55, 4, 10]), &tlv(0x0c, b"b")]);
    assert_eq!(with(seq(&[])).parse().unwrap().issuer.attributes.len(), 0);
    assert_eq!(flaw(&with(seq(&[&tlv(0x31, &[])]))), Flaw::Value);
    assert_eq!(flaw(&with(seq(&[&pair]))), Flaw::Tag);
    assert_eq!(flaw(&with(tlv(0x31, &tlv(0x31, &pair)))), Flaw::Tag);
    let set = tlv(0x31, &[pair.clone(), other.clone()].concat());
    let many = with(seq(&[&set])).parse().unwrap().issuer;
    assert_eq!(many.attributes.len(), 2);
    assert_eq!(many.attributes[1].value, b"b");
    assert_eq!(many.attributes[0].tag, 0x0c);
    let loose = seq(&[&oid(COMMON), &tlv(0x0c, b"a"), &tlv(5, &[])]);
    assert_eq!(flaw(&with(seq(&[&tlv(0x31, &loose)]))), Flaw::Trailing);
    let tiny = seq(&[&oid(COMMON)]);
    assert_eq!(flaw(&with(seq(&[&tlv(0x31, &tiny)]))), Flaw::Length);
    let numeric = seq(&[&tlv(2, &[1]), &tlv(0x0c, b"a")]);
    assert_eq!(flaw(&with(seq(&[&tlv(0x31, &numeric)]))), Flaw::Tag);
    let bytes = with(seq(&[&tlv(0x31, &pair)])).parse().unwrap().issuer.der;
    assert_eq!(bytes, seq(&[&tlv(0x31, &pair)]));
}

#[test]
fn listing() {
    let ext = extension(&[0x2b, 6, 1], None, &[1]);
    let dup = Parts::with(&[ext.clone(), ext.clone()]);
    assert_eq!(flaw(&dup), Flaw::Duplicate);
    let two = extension(&[0x2b, 6, 2], Some(true), &[1]);
    assert_eq!(
        Parts::with(&[ext.clone(), two])
            .parse()
            .unwrap()
            .extensions
            .len(),
        2
    );
    let apart = [ext.clone(), extension(&[0x2b, 6, 2], None, &[]), ext];
    assert_eq!(flaw(&Parts::with(&apart)), Flaw::Duplicate);
}

#[test]
fn falsehood() {
    let parts = single(&[0x2b, 6, 1], Some(false), &[1]);
    assert_eq!(flaw(&parts), Flaw::Value);
    let truth = single(&[0x2b, 6, 1], Some(true), &[1]).parse().unwrap();
    assert!(truth.extensions[0].critical);
    let plain = single(&[0x2b, 6, 1], None, &[1]).parse().unwrap();
    assert!(!plain.extensions[0].critical);
    let odd = seq(&[&oid(&[0x2b, 6, 1]), &tlv(1, &[1]), &tlv(4, &[1])]);
    assert_eq!(
        flaw(&Parts {
            extensions: wrap(&[odd]),
            ..Parts::base()
        }),
        Flaw::Value
    );
}

#[test]
fn hollow() {
    let parts = Parts {
        extensions: tlv(0xa3, &seq(&[])),
        ..Parts::base()
    };
    assert_eq!(flaw(&parts), Flaw::Value);
    let bare = Parts {
        extensions: tlv(0xa3, &[]),
        ..Parts::base()
    };
    assert_eq!(flaw(&bare), Flaw::Length);
}

#[test]
fn damaged() {
    let kind = seq(&[&oid(&[0x2b, 6, 1]), &tlv(5, &[])]);
    assert_eq!(
        flaw(&Parts {
            extensions: wrap(&[kind]),
            ..Parts::base()
        }),
        Flaw::Tag
    );
    let loose = seq(&[&oid(&[0x2b, 6, 1]), &tlv(4, &[1]), &tlv(5, &[])]);
    assert_eq!(
        flaw(&Parts {
            extensions: wrap(&[loose]),
            ..Parts::base()
        }),
        Flaw::Trailing
    );
    let named = seq(&[&tlv(4, &[1]), &tlv(4, &[1])]);
    assert_eq!(
        flaw(&Parts {
            extensions: wrap(&[named]),
            ..Parts::base()
        }),
        Flaw::Tag
    );
    let outer = Parts {
        extensions: tlv(0xa3, &[seq(&[]), seq(&[])].concat()),
        ..Parts::base()
    };
    assert_eq!(flaw(&outer), Flaw::Trailing);
    let broken = single(BASIC, None, &[0x30, 0x03, 0x01]);
    assert_eq!(flaw(&broken), Flaw::Length);
}

fn scheme(id: &[u8], params: Option<&[u8]>) -> (Scheme, Option<Vec<u8>>) {
    let parts = Parts {
        algorithm: alg(id, params),
        outer: alg(id, params),
        ..Parts::base()
    };
    let cert = parts.parse().unwrap();
    (cert.algorithm.scheme(), cert.algorithm.params)
}

fn arc(last: u8) -> Vec<u8> {
    vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, last]
}

fn curve(last: u8) -> Vec<u8> {
    vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, last]
}

#[test]
fn schemes() {
    let nil = [5u8, 0];
    assert_eq!(
        scheme(&arc(0x0b), Some(&nil)),
        (Scheme::Rsa256, Some(nil.to_vec()))
    );
    assert_eq!(scheme(&arc(0x0c), Some(&nil)).0, Scheme::Rsa384);
    assert_eq!(scheme(&arc(0x0d), Some(&nil)).0, Scheme::Rsa512);
    assert_eq!(scheme(&curve(2), None), (Scheme::Ecdsa256, None));
    assert_eq!(scheme(&curve(3), None).0, Scheme::Ecdsa384);
    assert_eq!(scheme(&curve(4), None).0, Scheme::Ecdsa512);
    assert_eq!(scheme(ECDSA256, None).0, Scheme::Ecdsa256);
    assert_eq!(scheme(RSA256, Some(&nil)).0, Scheme::Rsa256);
}

#[test]
fn others() {
    let nil = [5u8, 0];
    let odd = seq(&[&int(&[1])]);
    assert_eq!(scheme(&arc(0x0b), None).0, Scheme::Other);
    assert_eq!(scheme(&arc(0x0b), Some(&odd)).0, Scheme::Other);
    assert_eq!(scheme(&arc(0x0e), Some(&nil)).0, Scheme::Other);
    assert_eq!(scheme(&arc(0x0a), Some(&odd)).0, Scheme::Other);
    assert_eq!(scheme(&curve(2), Some(&nil)).0, Scheme::Other);
    assert_eq!(scheme(&curve(2), Some(&odd)).0, Scheme::Other);
    assert_eq!(scheme(&curve(1), None).0, Scheme::Other);
    assert_eq!(scheme(&curve(5), None).0, Scheme::Other);
    assert_eq!(scheme(&[0x2b, 0x65, 0x70], None).0, Scheme::Other);
    assert_eq!(scheme(&arc(0x0a), Some(&odd)).1, Some(odd));
}

#[test]
fn identifier() {
    let loose = seq(&[&oid(ECDSA256), &[5, 0], &[5, 0]]);
    let parts = Parts {
        algorithm: loose.clone(),
        outer: loose,
        ..Parts::base()
    };
    assert_eq!(flaw(&parts), Flaw::Trailing);
    let bare = Parts {
        algorithm: seq(&[]),
        outer: seq(&[]),
        ..Parts::base()
    };
    assert_eq!(flaw(&bare), Flaw::Length);
    let kind = Parts {
        algorithm: seq(&[&tlv(4, &[1])]),
        outer: seq(&[&tlv(4, &[1])]),
        ..Parts::base()
    };
    assert_eq!(flaw(&kind), Flaw::Tag);
    let set = Parts {
        algorithm: tlv(0x31, &oid(ECDSA256)),
        outer: tlv(0x31, &oid(ECDSA256)),
        ..Parts::base()
    };
    assert_eq!(flaw(&set), Flaw::Tag);
}

#[test]
fn twin() {
    let both = |first: Option<bool>, second: Option<bool>| {
        let one = extension(&[0x2b, 6, 1], first, &[1]);
        let two = extension(&[0x2b, 6, 1], second, &[1]);
        Parts::with(&[one, two])
    };
    assert_eq!(flaw(&both(Some(true), Some(true))), Flaw::Duplicate);
    assert_eq!(flaw(&both(Some(true), None)), Flaw::Duplicate);
    assert_eq!(flaw(&both(None, Some(true))), Flaw::Duplicate);
    assert_eq!(flaw(&both(None, None)), Flaw::Duplicate);
}

#[test]
fn leftovers() {
    let name = seq(&[]);
    assert!(Name::parse(&name).is_ok());
    assert_eq!(
        Name::parse(&[name.clone(), vec![0]].concat()).unwrap_err(),
        Flaw::Trailing
    );
    let id = alg(ECDSA256, None);
    assert!(Algorithm::parse(&id).is_ok());
    assert_eq!(
        Algorithm::parse(&[id.clone(), vec![0]].concat()).unwrap_err(),
        Flaw::Trailing
    );
    let key = spki(P256, &point());
    assert!(Public::parse(&key).is_ok());
    assert_eq!(
        Public::parse(&[key.clone(), vec![0]].concat()).unwrap_err(),
        Flaw::Trailing
    );
    assert_eq!(Name::parse(&[]).unwrap_err(), Flaw::Length);
    assert_eq!(Algorithm::parse(&[]).unwrap_err(), Flaw::Length);
    assert_eq!(Public::parse(&[]).unwrap_err(), Flaw::Length);
}

#[test]
fn bare() {
    let nil = [5u8, 0];
    assert_eq!(scheme(&arc(0x0c), None).0, Scheme::Other);
    assert_eq!(scheme(&arc(0x0d), None).0, Scheme::Other);
    assert_eq!(scheme(&curve(3), Some(&nil)).0, Scheme::Other);
    assert_eq!(scheme(&curve(4), Some(&nil)).0, Scheme::Other);
    assert_eq!(scheme(&curve(3), Some(&seq(&[]))).0, Scheme::Other);
    assert_eq!(scheme(&curve(4), Some(&seq(&[]))).0, Scheme::Other);
}

const ALL: [&str; 6] = [RFCRSA, RFCEC, RSA, CA, P384, P521];

#[test]
fn rewritten() {
    for text in ALL {
        let wire = hex(text);
        let cert = Certificate::parse(&wire).unwrap();
        assert_eq!(rewrite(&wire, Some(2), true), wire);
        for (number, version) in [(None, 1), (Some(1), 2)] {
            let other = Certificate::parse(&rewrite(&wire, number, false)).unwrap();
            assert_eq!(other.version, version);
            assert!(other.extensions.is_empty());
            assert_eq!(
                (other.serial, other.signature),
                (cert.serial.clone(), cert.signature.clone())
            );
            assert_eq!(
                (other.issuer, other.subject),
                (cert.issuer.clone(), cert.subject.clone())
            );
            assert_eq!((other.from, other.until), (cert.from, cert.until));
            assert_eq!(
                (other.key, other.spki),
                (cert.key.clone(), cert.spki.clone())
            );
            assert_eq!(
                (other.algorithm, other.outer),
                (cert.algorithm.clone(), cert.outer.clone())
            );
            assert!(other.alt.is_none() && other.usage.is_none());
        }
    }
}

#[test]
fn forbidden() {
    for text in ALL {
        let wire = hex(text);
        let has = !Certificate::parse(&wire).unwrap().extensions.is_empty();
        for number in [0, 3] {
            let bent = rewrite(&wire, Some(number), false);
            assert_eq!(Certificate::parse(&bent).unwrap_err(), Flaw::Version);
        }
        for number in [None, Some(1)] {
            let bent = Certificate::parse(&rewrite(&wire, number, true));
            assert_eq!(bent.err(), has.then_some(Flaw::Version), "{text:.12}");
        }
    }
}
