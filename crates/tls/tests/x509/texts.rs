use crate::data::{CA, P384, P521, RFCEC, RFCRSA, RSA};
use crate::support::{COMMON, Parts, load, oid, seq, tlv};
use tls::x509::{Name, Oid};

const ORG: &[u8] = &[0x55, 0x04, 0x0a];
const COUNTRY: &[u8] = &[0x55, 0x04, 0x06];

fn attr(id: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x31, &seq(&[&oid(id), &tlv(tag, value)]))
}

fn text(items: &[Vec<u8>], id: &[u8]) -> Option<String> {
    let refs: Vec<&[u8]> = items.iter().map(|each| each.as_slice()).collect();
    let parts = Parts {
        subject: seq(&refs),
        ..Parts::base()
    };
    let cert = parts.parse().unwrap();
    cert.subject.text(&Oid::parse(id).unwrap())
}

fn one(tag: u8, value: &[u8]) -> Option<String> {
    text(&[attr(COMMON, tag, value)], COMMON)
}

#[test]
fn utf() {
    assert_eq!(one(0x0c, "héllo".as_bytes()), Some("héllo".into()));
    assert_eq!(one(0x0c, b""), Some(String::new()));
    assert_eq!(one(0x0c, &[0xff]), None);
    assert_eq!(one(0x0c, &[0xc3]), None);
}

#[test]
fn ia5() {
    assert_eq!(one(0x16, b"a@b.test"), Some("a@b.test".into()));
    assert_eq!(one(0x16, &[0x7f]), Some("\u{7f}".into()));
    assert_eq!(one(0x16, &[0x80]), None);
    assert_eq!(one(0x16, "é".as_bytes()), None);
}

#[test]
fn printable() {
    let all = "AZaz09 '()+,-./:=?";
    assert_eq!(one(0x13, all.as_bytes()), Some(all.into()));
    for bad in [
        "@", "*", "&", "_", "!", "\"", "<", "é", "\n", "~", "#", "$", "%", ";",
    ] {
        assert_eq!(one(0x13, bad.as_bytes()), None, "{bad}");
    }
    assert_eq!(one(0x13, b"ok@"), None);
    assert_eq!(one(0x13, b""), Some(String::new()));
}

#[test]
fn others() {
    for tag in [0x12, 0x14, 0x1a, 0x1c, 0x1e, 0x04, 0x05] {
        assert_eq!(one(tag, b"abc"), None, "{tag}");
    }
}

#[test]
fn first() {
    let both = [attr(COMMON, 0x0c, b"one"), attr(COMMON, 0x0c, b"two")];
    assert_eq!(text(&both, COMMON), Some("one".into()));
    let bad = [attr(COMMON, 0x13, b"@"), attr(COMMON, 0x0c, b"two")];
    assert_eq!(text(&bad, COMMON), None);
    let mixed = [attr(ORG, 0x0c, b"org"), attr(COMMON, 0x0c, b"cn")];
    assert_eq!(text(&mixed, COMMON), Some("cn".into()));
    assert_eq!(text(&mixed, ORG), Some("org".into()));
}

#[test]
fn absent() {
    let only = [attr(ORG, 0x0c, b"org")];
    assert_eq!(text(&only, COMMON), None);
    assert_eq!(text(&[], COMMON), None);
}

fn pick(name: &Name) -> Vec<Option<String>> {
    let each = |id: &[u8]| name.text(&Oid::parse(id).unwrap());
    vec![each(COMMON), each(ORG), each(COUNTRY)]
}

fn some(items: [Option<&str>; 3]) -> Vec<Option<String>> {
    items.iter().map(|item| item.map(String::from)).collect()
}

#[test]
fn vectors() {
    let rsa = some([Some("rsa"), None, None]);
    let ec = some([Some("ecdsa256"), None, None]);
    let leaf = some([Some("leaf.example.test"), Some("Osistack Test"), Some("US")]);
    let root = some([Some("Wurzel CA é"), Some("Wurzel"), Some("DE")]);
    let p384 = some([Some("p384.test"), None, None]);
    let p521 = some([Some("p521.test"), None, None]);
    let issuer = some([None, Some("Issuer"), None]);
    let cases = [
        (RFCRSA, rsa.clone(), rsa),
        (RFCEC, ec.clone(), ec),
        (RSA, leaf.clone(), leaf),
        (CA, root.clone(), root),
        (P384, p384.clone(), p384),
        (P521, p521, issuer),
    ];
    for (text, subject, issuer) in cases {
        let cert = load(text).1;
        assert_eq!(pick(&cert.subject), subject);
        assert_eq!(pick(&cert.issuer), issuer);
    }
}
