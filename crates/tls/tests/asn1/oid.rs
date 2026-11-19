use tls::x509::{Flaw, Oid};

fn text(content: &[u8]) -> String {
    Oid::parse(content).unwrap().to_string()
}

#[test]
fn dotted() {
    let rsa = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let oid = Oid::parse(&rsa).unwrap();
    assert_eq!(oid.to_string(), "1.2.840.113549.1.1.11");
    assert_eq!(oid.arcs(), [1, 2, 840, 113549, 1, 1, 11]);
    assert_eq!(oid.bytes(), rsa);
    assert_eq!(text(&[0x55, 0x1d, 0x13]), "2.5.29.19");
    assert_eq!(text(&[0x2b, 0x81, 0x04, 0x00, 0x22]), "1.3.132.0.34");
}

#[test]
fn heads() {
    assert_eq!(text(&[0x00]), "0.0");
    assert_eq!(text(&[0x27]), "0.39");
    assert_eq!(text(&[0x28]), "1.0");
    assert_eq!(text(&[0x4f]), "1.39");
    assert_eq!(text(&[0x50]), "2.0");
    assert_eq!(text(&[0x88, 0x37]), "2.999");
    assert_eq!(Oid::parse(&[0x88, 0x37]).unwrap().arcs(), [2, 999]);
}

#[test]
fn empty() {
    assert_eq!(Oid::parse(&[]), Err(Flaw::Value));
}

#[test]
fn dangling() {
    assert_eq!(Oid::parse(&[0x2a, 0x86]), Err(Flaw::Value));
    assert_eq!(Oid::parse(&[0x86]), Err(Flaw::Value));
    assert_eq!(Oid::parse(&[0x2a, 0xff, 0xff]), Err(Flaw::Value));
}

#[test]
fn padded() {
    assert_eq!(Oid::parse(&[0x2a, 0x80, 0x01]), Err(Flaw::Minimal));
    assert_eq!(Oid::parse(&[0x80, 0x01]), Err(Flaw::Minimal));
    assert!(Oid::parse(&[0x2a, 0x81, 0x80, 0x00]).is_ok());
    assert_eq!(Oid::parse(&[0x2a, 0x80, 0x80, 0x01]), Err(Flaw::Minimal));
}

#[test]
fn widest() {
    let top = [0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
    let oid = Oid::parse(&top).unwrap();
    assert_eq!(oid.arcs(), [1, 3, i64::MAX as u64]);
    let max = [
        0x2b, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    assert_eq!(Oid::parse(&max).unwrap().arcs(), [1, 3, u64::MAX]);
    let over = [
        0x2b, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ];
    assert_eq!(Oid::parse(&over), Err(Flaw::Value));
    let long = [
        0x2b, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    ];
    assert_eq!(Oid::parse(&long), Err(Flaw::Value));
}

#[test]
fn building() {
    let rsa = [1, 2, 840, 113549, 1, 1, 11];
    let oid = Oid::from(&rsa);
    assert_eq!(
        oid.bytes(),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
    );
    assert_eq!(oid, Oid::parse(oid.bytes()).unwrap());
    assert_eq!(Oid::from(&[2, 5, 4, 3]).bytes(), [0x55, 0x04, 0x03]);
    assert_eq!(Oid::from(&[2, 999]).bytes(), [0x88, 0x37]);
    assert_eq!(Oid::from(&[1, 3, 1 << 62]).arcs(), [1, 3, 1 << 62]);
    assert_ne!(Oid::from(&[2, 5, 4, 3]), Oid::from(&[2, 5, 4, 6]));
}
