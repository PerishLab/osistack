use crate::support::{EC, P256, Parts, RSA, alg, bits, flaw, int, oid, point, seq, spki, tlv};
use tls::x509::{Curve, Flaw, Public};

fn rsa(modulus: &[u8], exponent: &[u8]) -> Parts {
    let key = seq(&[&int(modulus), &int(exponent)]);
    let algorithm = alg(RSA, Some(&[5, 0]));
    Parts {
        spki: seq(&[&algorithm, &bits(0, &key)]),
        ..Parts::base()
    }
}

#[test]
fn modulus() {
    let cert = rsa(&[0, 0x80, 1, 2], &[1, 0, 1]).parse().unwrap();
    let want = Public::Rsa {
        modulus: vec![0x80, 1, 2],
        exponent: vec![1, 0, 1],
    };
    assert_eq!(cert.key, want);
    let small = rsa(&[0x7f, 1], &[3]).parse().unwrap();
    assert_eq!(
        small.key,
        Public::Rsa {
            modulus: vec![0x7f, 1],
            exponent: vec![3]
        }
    );
    assert_eq!(flaw(&rsa(&[0x80, 1], &[3])), Flaw::Value);
    assert_eq!(flaw(&rsa(&[0x7f, 1], &[0xff])), Flaw::Value);
    assert_eq!(flaw(&rsa(&[0], &[3])), Flaw::Value);
    assert_eq!(flaw(&rsa(&[0x7f], &[0])), Flaw::Value);
    assert_eq!(flaw(&rsa(&[0, 1], &[3])), Flaw::Minimal);
    assert_eq!(flaw(&rsa(&[], &[3])), Flaw::Value);
}

fn inside(params: Option<&[u8]>, key: &[u8], unused: u8) -> Parts {
    Parts {
        spki: seq(&[&alg(RSA, params), &bits(unused, key)]),
        ..Parts::base()
    }
}

#[test]
fn rsashape() {
    let good = seq(&[&int(&[0x7f]), &int(&[3])]);
    assert!(inside(Some(&[5, 0]), &good, 0).parse().is_ok());
    assert_eq!(flaw(&inside(None, &good, 0)), Flaw::Value);
    assert_eq!(flaw(&inside(Some(&oid(P256)), &good, 0)), Flaw::Value);
    assert_eq!(flaw(&inside(Some(&[5, 1, 0]), &good, 0)), Flaw::Value);
    assert_eq!(flaw(&inside(Some(&[5, 0]), &good, 2)), Flaw::Value);
    let three = seq(&[&int(&[0x7f]), &int(&[3]), &int(&[1])]);
    assert_eq!(flaw(&inside(Some(&[5, 0]), &three, 0)), Flaw::Trailing);
    let one = seq(&[&int(&[0x7f])]);
    assert_eq!(flaw(&inside(Some(&[5, 0]), &one, 0)), Flaw::Length);
    assert_eq!(flaw(&inside(Some(&[5, 0]), &tlv(0x31, &[]), 0)), Flaw::Tag);
    let more = [good.clone(), vec![0]].concat();
    assert_eq!(flaw(&inside(Some(&[5, 0]), &more, 0)), Flaw::Trailing);
    let kind = seq(&[&tlv(4, &[1]), &int(&[3])]);
    assert_eq!(flaw(&inside(Some(&[5, 0]), &kind, 0)), Flaw::Tag);
}

fn curved(curve: &[u8], point: &[u8]) -> Result<Public, Flaw> {
    let parts = Parts {
        spki: spki(curve, point),
        ..Parts::base()
    };
    parts.parse().map(|cert| cert.key)
}

fn sized(count: usize) -> Vec<u8> {
    let mut out = vec![4u8];
    out.extend(vec![7; count - 1]);
    out
}

#[test]
fn curves() {
    let p384 = [0x2b, 0x81, 4, 0, 0x22];
    let p521 = [0x2b, 0x81, 4, 0, 0x23];
    let wire = point();
    assert_eq!(
        curved(P256, &wire),
        Ok(Public::Ec {
            curve: Curve::P256,
            point: wire
        })
    );
    let big = sized(97);
    assert_eq!(
        curved(&p384, &big),
        Ok(Public::Ec {
            curve: Curve::P384,
            point: big
        })
    );
    let huge = sized(133);
    assert_eq!(
        curved(&p521, &huge),
        Ok(Public::Ec {
            curve: Curve::P521,
            point: huge
        })
    );
    assert_eq!(curved(&p384, &sized(65)), Err(Flaw::Value));
    assert_eq!(curved(&p521, &sized(97)), Err(Flaw::Value));
    assert_eq!(curved(P256, &sized(97)), Err(Flaw::Value));
    assert_eq!(curved(P256, &sized(133)), Err(Flaw::Value));
}

#[test]
fn points() {
    assert_eq!(curved(P256, &sized(64)), Err(Flaw::Value));
    assert_eq!(curved(P256, &sized(66)), Err(Flaw::Value));
    assert_eq!(curved(P256, &[]), Err(Flaw::Value));
    let mut packed = sized(65);
    packed[0] = 2;
    assert_eq!(curved(P256, &packed[..33]), Err(Flaw::Value));
    assert_eq!(curved(P256, &packed), Err(Flaw::Value));
    packed[0] = 5;
    assert_eq!(curved(P256, &packed), Err(Flaw::Value));
    packed[0] = 0;
    assert_eq!(curved(P256, &packed), Err(Flaw::Value));
}

#[test]
fn unknown() {
    let k1 = [0x2b, 0x81, 4, 0, 0x0a];
    let key = curved(&k1, &sized(65)).unwrap();
    let Public::Other(algorithm, data) = key else {
        panic!("other");
    };
    assert_eq!(algorithm.id.bytes(), EC);
    assert_eq!(algorithm.params, Some(oid(&k1)));
    assert_eq!(data, sized(65));
    assert_eq!(curved(&k1, &[]).unwrap(), Public::Other(algorithm, vec![]));
}

fn keyed(params: Option<&[u8]>) -> Result<Public, Flaw> {
    let parts = Parts {
        spki: seq(&[&alg(EC, params), &bits(0, &point())]),
        ..Parts::base()
    };
    parts.parse().map(|cert| cert.key)
}

#[test]
fn params() {
    assert_eq!(keyed(None), Err(Flaw::Value));
    assert_eq!(keyed(Some(&[5, 0])), Err(Flaw::Value));
    assert_eq!(keyed(Some(&tlv(2, &[1]))), Err(Flaw::Value));
    let explicit = seq(&[&int(&[1])]);
    let Ok(Public::Other(algorithm, _)) = keyed(Some(&explicit)) else {
        panic!("explicit");
    };
    assert_eq!(algorithm.params, Some(explicit));
    assert_eq!(
        keyed(Some(&[&oid(P256)[..], &[5, 0]].concat())),
        Err(Flaw::Trailing)
    );
    let unused = Parts {
        spki: seq(&[&alg(EC, Some(&oid(P256))), &bits(1, &[4, 2])]),
        ..Parts::base()
    };
    assert_eq!(flaw(&unused), Flaw::Value);
}

#[test]
fn foreign() {
    let ed = [0x2b, 0x65, 0x70];
    let parts = Parts {
        spki: seq(&[&alg(&ed, None), &bits(0, &[1; 32])]),
        ..Parts::base()
    };
    let Public::Other(algorithm, data) = parts.parse().unwrap().key else {
        panic!("other");
    };
    assert_eq!(
        (algorithm.id.bytes(), algorithm.params, data),
        (&ed[..], None, vec![1; 32])
    );
    let loose = Parts {
        spki: seq(&[&alg(&ed, None), &bits(3, &[0x08])]),
        ..Parts::base()
    };
    assert_eq!(flaw(&loose), Flaw::Value);
    let more = Parts {
        spki: seq(&[&alg(&ed, None), &bits(0, &[1]), &[5, 0]]),
        ..Parts::base()
    };
    assert_eq!(flaw(&more), Flaw::Trailing);
    let bare = Parts {
        spki: seq(&[&alg(&ed, None)]),
        ..Parts::base()
    };
    assert_eq!(flaw(&bare), Flaw::Length);
}
