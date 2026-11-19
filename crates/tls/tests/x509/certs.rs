use crate::data::{CA, P384, P521, RFCEC, RFCRSA, RSA};
use crate::support::{find, listed, load, shape, when};
use tls::x509::{Basic, Curve, General, Public, Scheme};

fn tail(bytes: &[u8], count: usize) -> &[u8] {
    &bytes[bytes.len() - count..]
}

#[test]
fn rfcrsa() {
    let (wire, cert) = load(RFCRSA);
    assert_eq!(
        (wire.len(), cert.version, cert.serial.as_slice()),
        (432, 3, &[2][..])
    );
    assert_eq!(cert.algorithm.scheme(), Scheme::Rsa256);
    assert_eq!(cert.algorithm.params, Some(vec![5, 0]));
    assert_eq!(cert.outer, cert.algorithm);
    assert_eq!(shape(&cert.issuer), ["2.5.4.3/13/rsa"]);
    assert_eq!(cert.subject, cert.issuer);
    assert_eq!(cert.from, when((2016, 7, 30), (1, 23, 59)));
    assert_eq!(cert.until, when((2026, 7, 30), (1, 23, 59)));
    assert_eq!(
        (cert.from.unix(), cert.until.unix()),
        (1469841839, 1785374639)
    );
    let Public::Rsa { modulus, exponent } = &cert.key else {
        panic!("rsa");
    };
    assert_eq!(
        (modulus.len(), &modulus[..4]),
        (128, &[0xb4, 0xbb, 0x49, 0x8f][..])
    );
    assert_eq!(
        (tail(modulus, 4), exponent.as_slice()),
        (&[0x9f, 0x7f, 0x1e, 0x3f][..], &[1, 0, 1][..])
    );
    assert_eq!(listed(&cert), ["2.5.29.19/false/2", "2.5.29.15/false/4"]);
    assert_eq!(
        cert.basic,
        Some(Basic {
            ca: false,
            depth: None
        })
    );
    assert_eq!((cert.usage, cert.alt, cert.purposes), (Some(5), None, None));
    assert_eq!(
        (cert.signature.len(), &cert.signature[..4]),
        (128, &[0x85, 0xaa, 0xd2, 0xa0][..])
    );
    assert_eq!(tail(&cert.signature, 4), [0xb4, 0x2b, 0x4d, 0xe1]);
}

#[test]
fn rfcec() {
    let (wire, cert) = load(RFCEC);
    assert_eq!(
        (wire.len(), cert.version, cert.serial.as_slice()),
        (306, 3, &[7][..])
    );
    assert_eq!(cert.algorithm.scheme(), Scheme::Ecdsa256);
    assert_eq!(cert.algorithm.params, None);
    assert_eq!(shape(&cert.subject), ["2.5.4.3/13/ecdsa256"]);
    assert_eq!(cert.from, when((2016, 7, 30), (1, 24, 0)));
    assert_eq!(
        (cert.from.unix(), cert.until.unix()),
        (1469841840, 1785374640)
    );
    let Public::Ec { curve, point } = &cert.key else {
        panic!("ec");
    };
    assert_eq!(
        (*curve, point.len(), &point[..4]),
        (Curve::P256, 65, &[4, 8, 0xd5, 0x30][..])
    );
    assert_eq!(tail(point, 4), [0x58, 0x94, 0x8d, 0xd0]);
    assert_eq!(listed(&cert), ["2.5.29.19/false/2", "2.5.29.15/false/4"]);
    assert_eq!(
        (cert.usage, cert.basic.map(|basic| basic.ca)),
        (Some(1), Some(false))
    );
    assert_eq!(
        (cert.signature.len(), &cert.signature[..4]),
        (71, &[0x30, 0x45, 2, 0x21][..])
    );
    assert_eq!(tail(&cert.signature, 4), [0x3e, 0x01, 0x1d, 0x11]);
}

#[test]
fn rsa2048() {
    let (wire, cert) = load(RSA);
    assert_eq!((wire.len(), cert.version, cert.serial.len()), (995, 3, 20));
    assert_eq!(
        hexed(&cert.serial),
        "1234567890abcdef1234567890abcdef12345678"
    );
    assert_eq!(cert.algorithm.scheme(), Scheme::Rsa256);
    let want = [
        "2.5.4.6/13/US",
        "2.5.4.10/0c/Osistack Test",
        "2.5.4.3/0c/leaf.example.test",
    ];
    assert_eq!(shape(&cert.subject), want);
    assert_eq!(shape(&cert.issuer), want);
    assert_eq!(cert.from, when((2026, 1, 2), (3, 4, 5)));
    assert_eq!(cert.until, when((2030, 12, 31), (23, 59, 58)));
    assert_eq!(
        (cert.from.unix(), cert.until.unix()),
        (1767323045, 1924991998)
    );
    let Public::Rsa { modulus, exponent } = &cert.key else {
        panic!("rsa");
    };
    assert_eq!(
        (modulus.len(), &modulus[..4]),
        (256, &[0xd0, 0x67, 0x6e, 0x1c][..])
    );
    assert_eq!(
        (tail(modulus, 4), exponent.as_slice()),
        (&[0xf1, 0x24, 0x52, 0x67][..], &[1, 0, 1][..])
    );
    let want = [
        "2.5.29.17/false/102",
        "2.5.29.19/true/2",
        "2.5.29.15/true/4",
        "2.5.29.37/false/22",
        "2.5.29.14/false/22",
    ];
    assert_eq!(listed(&cert), want);
    assert_eq!(
        cert.basic,
        Some(Basic {
            ca: false,
            depth: None
        })
    );
    assert_eq!(cert.usage, Some(5));
    assert_eq!(
        (cert.signature.len(), &cert.signature[..4]),
        (256, &[0x1c, 0xd4, 0xc4, 0xfc][..])
    );
    assert_eq!(tail(&cert.signature, 4), [0xe2, 0x4f, 0x96, 0xd6]);
}

fn hexed(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn forms() {
    let (_, cert) = load(RSA);
    let want = vec![
        General::Dns("leaf.example.test".into()),
        General::Dns("*.example.test".into()),
        General::Ip(vec![192, 0, 2, 7]),
        General::Ip(vec![
            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        General::Email("ops@example.test".into()),
        General::Uri("https://example.test/".into()),
    ];
    assert_eq!(cert.alt, Some(want));
    let names: Vec<String> = cert
        .purposes
        .unwrap()
        .iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(names, ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]);
}

#[test]
fn ca256() {
    let (wire, cert) = load(CA);
    assert_eq!(
        (wire.len(), cert.version, cert.serial.as_slice()),
        (390, 3, &[1][..])
    );
    assert_eq!(cert.algorithm.scheme(), Scheme::Ecdsa256);
    let want = [
        "2.5.4.6/13/DE",
        "2.5.4.10/0c/Wurzel",
        "2.5.4.3/0c/Wurzel CA é",
    ];
    assert_eq!(shape(&cert.subject), want);
    assert_eq!(cert.from, when((2049, 12, 31), (23, 59, 59)));
    assert_eq!(cert.until, when((2051, 6, 7), (8, 9, 10)));
    assert_eq!(
        (cert.from.unix(), cert.until.unix()),
        (2524607999, 2569738150)
    );
    let Public::Ec { curve, point } = &cert.key else {
        panic!("ec");
    };
    assert_eq!(
        (*curve, point.len(), &point[..5]),
        (Curve::P256, 65, &[4, 0x9b, 0x6f, 0x11, 0x61][..])
    );
    assert_eq!(tail(point, 4), [0x63, 0xb6, 0x92, 0xe8]);
    assert_eq!(listed(&cert), ["2.5.29.19/true/8", "2.5.29.15/true/4"]);
    assert_eq!(
        cert.basic,
        Some(Basic {
            ca: true,
            depth: Some(0)
        })
    );
    assert_eq!(cert.usage, Some(0x60));
    assert_eq!(
        (cert.signature.len(), tail(&cert.signature, 4)),
        (72, &[0x61, 0xed, 0x39, 0xac][..])
    );
}

#[test]
fn p384() {
    let (wire, cert) = load(P384);
    assert_eq!(
        (wire.len(), cert.version, cert.serial.as_slice()),
        (342, 3, &[0, 0x80][..])
    );
    assert_eq!(cert.algorithm.scheme(), Scheme::Ecdsa384);
    assert_eq!(shape(&cert.subject), ["2.5.4.3/0c/p384.test"]);
    assert_eq!(cert.from, when((1999, 12, 31), (0, 0, 0)));
    assert_eq!(cert.until, when((2049, 12, 31), (23, 59, 59)));
    assert_eq!(
        (cert.from.unix(), cert.until.unix()),
        (946598400, 2524607999)
    );
    let Public::Ec { curve, point } = &cert.key else {
        panic!("ec");
    };
    assert_eq!(
        (*curve, point.len(), &point[..5]),
        (Curve::P384, 97, &[4, 0xac, 0x50, 0xaa, 0xc2][..])
    );
    assert_eq!(tail(point, 4), [0x14, 0x9e, 0x73, 0x94]);
    assert!(cert.extensions.is_empty());
    assert!(cert.alt.is_none());
    assert!(cert.basic.is_none());
    assert!(cert.usage.is_none());
    assert!(cert.purposes.is_none());
    assert_eq!(
        (cert.signature.len(), tail(&cert.signature, 4)),
        (103, &[0x14, 0x5e, 0xcf, 0x5f][..])
    );
}

#[test]
fn p521() {
    let (wire, cert) = load(P521);
    assert_eq!((wire.len(), cert.version, cert.serial.len()), (365, 3, 20));
    assert_eq!(cert.serial[0], 0x40);
    assert!(cert.serial[1..].iter().all(|byte| *byte == 0));
    assert_eq!(cert.algorithm.scheme(), Scheme::Ecdsa512);
    assert_eq!(shape(&cert.subject), ["2.5.4.3/0c/p521.test"]);
    assert_eq!(shape(&cert.issuer), ["2.5.4.10/0c/Issuer"]);
    assert_eq!(cert.from, when((2000, 2, 29), (12, 0, 0)));
    assert_eq!(cert.until, when((2000, 3, 1), (0, 0, 0)));
    assert_eq!(
        (cert.from.unix(), cert.until.unix()),
        (951825600, 951868800)
    );
    let Public::Ec { curve, point } = &cert.key else {
        panic!("ec");
    };
    assert_eq!(
        (*curve, point.len(), &point[..5]),
        (Curve::P521, 133, &[4, 0, 0x77, 0x3f, 0x9a][..])
    );
    assert_eq!(tail(point, 4), [0x1f, 0x16, 0xb3, 0xf6]);
    assert_eq!(
        (cert.signature.len(), tail(&cert.signature, 4)),
        (72, &[0xa4, 0xb9, 0x93, 0x12][..])
    );
}

#[test]
fn slices() {
    let cases = [(RFCRSA, 95, 281), (RFCEC, 101, 216), (RSA, 216, 715)];
    let more = [(CA, 172, 299), (P384, 104, 220), (P521, 120, 274)];
    for (text, spki, size) in cases.into_iter().chain(more) {
        let (wire, cert) = load(text);
        assert_eq!((find(&wire, &cert.tbs), cert.tbs.len()), (Some(4), size));
        assert_eq!(find(&wire, &cert.spki), Some(spki));
        assert_eq!(find(&cert.tbs, &cert.spki), Some(spki - 4));
        assert_eq!(&wire[wire.len() - cert.signature.len()..], cert.signature);
    }
}
