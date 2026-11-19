use crate::support::tlv;
use tls::x509::{Der, Flaw, bits, boolean, integer, unsigned};

fn read(wire: &[u8]) -> Result<(u8, Vec<u8>), Flaw> {
    Der::new(wire)
        .read()
        .map(|(tag, body)| (tag, body.to_vec()))
}

#[test]
fn short() {
    let mut der = Der::new(&[4, 2, 1, 2, 5, 0]);
    assert_eq!(der.peek(), Some(4));
    assert_eq!(der.read(), Ok((4, &[1, 2][..])));
    assert_eq!((der.peek(), der.done()), (Some(5), false));
    assert_eq!(der.read(), Ok((5, &[][..])));
    assert_eq!((der.peek(), der.done()), (None, true));
    assert_eq!(der.finish(), Ok(()));
}

#[test]
fn whole() {
    let wire = [0x30, 3, 2, 1, 7, 9];
    let mut der = Der::new(&wire);
    assert_eq!(der.raw(), Ok((0x30, &[2, 1, 7][..], &wire[..5])));
    assert_eq!(der.finish(), Err(Flaw::Trailing));
}

#[test]
fn edge127() {
    let body = vec![7u8; 127];
    let wire = tlv(4, &body);
    assert_eq!(wire[1], 127);
    assert_eq!(read(&wire), Ok((4, body)));
}

#[test]
fn edge128() {
    let body = vec![7u8; 128];
    let wire = tlv(4, &body);
    assert_eq!(&wire[..3], &[4, 0x81, 0x80]);
    assert_eq!(read(&wire), Ok((4, body)));
}

#[test]
fn edge255() {
    let body = vec![7u8; 255];
    let wire = tlv(4, &body);
    assert_eq!(&wire[..3], &[4, 0x81, 0xff]);
    assert_eq!(read(&wire), Ok((4, body)));
}

#[test]
fn edge256() {
    let body = vec![7u8; 256];
    let wire = tlv(4, &body);
    assert_eq!(&wire[..4], &[4, 0x82, 1, 0]);
    assert_eq!(read(&wire), Ok((4, body)));
}

#[test]
fn longer() {
    let wire = [&[4u8, 0x83, 1, 0, 0][..], &vec![0u8; 65536]].concat();
    assert_eq!(read(&wire).unwrap().1.len(), 65536);
    let four = [&[4u8, 0x84, 1, 0, 0, 0][..], &[0u8; 8]].concat();
    assert_eq!(read(&four), Err(Flaw::Length));
}

#[test]
fn needless() {
    assert_eq!(read(&[4, 0x81, 0x7f]), Err(Flaw::Minimal));
    assert_eq!(read(&[4, 0x81, 0x01, 0]), Err(Flaw::Minimal));
    assert_eq!(read(&[4, 0x81, 0x00]), Err(Flaw::Minimal));
}

#[test]
fn leading() {
    assert_eq!(read(&[4, 0x82, 0x00, 0xff, 0]), Err(Flaw::Minimal));
    assert_eq!(read(&[4, 0x82, 0x00, 0x80, 0]), Err(Flaw::Minimal));
    assert_eq!(read(&[4, 0x82, 0x00, 0x00]), Err(Flaw::Minimal));
}

#[test]
fn indefinite() {
    assert_eq!(read(&[0x30, 0x80, 0, 0]), Err(Flaw::Length));
    assert_eq!(read(&[0x30, 0x80]), Err(Flaw::Length));
}

#[test]
fn wide() {
    let wire = [&[4u8, 0x85, 0, 0, 0, 0, 1][..], &[0]].concat();
    assert_eq!(read(&wire), Err(Flaw::Length));
    assert_eq!(read(&[4, 0xff]), Err(Flaw::Length));
}

#[test]
fn exceeds() {
    assert_eq!(read(&[4, 3, 1, 2]), Err(Flaw::Length));
    assert_eq!(read(&[4, 0x81, 0x80, 1]), Err(Flaw::Length));
    assert_eq!(
        read(&[4, 0x84, 0xff, 0xff, 0xff, 0xff, 1]),
        Err(Flaw::Length)
    );
    assert_eq!(read(&[4, 0x82, 1]), Err(Flaw::Length));
    assert_eq!(read(&[4, 0x81]), Err(Flaw::Length));
    assert_eq!(read(&[4]), Err(Flaw::Length));
    assert_eq!(read(&[]), Err(Flaw::Length));
}

#[test]
fn high() {
    assert_eq!(read(&[0x1f, 1, 0]), Err(Flaw::Tag));
    assert_eq!(read(&[0x3f, 1, 0]), Err(Flaw::Tag));
    assert_eq!(read(&[0xdf, 1, 0]), Err(Flaw::Tag));
    assert_eq!(read(&[0xbf, 0x81, 0]), Err(Flaw::Tag));
    assert_eq!(read(&[0x1e, 0]), Ok((0x1e, vec![])));
    assert_eq!(read(&[0x0f, 0]), Ok((0x0f, vec![])));
    assert_eq!(read(&[0x2f, 0]), Ok((0x2f, vec![])));
}

#[test]
fn expect() {
    let mut der = Der::new(&[2, 1, 5, 4, 0]);
    assert_eq!(der.expect(2), Ok(&[5][..]));
    assert_eq!(der.expect(2), Err(Flaw::Tag));
    assert_eq!(der.expect(4), Err(Flaw::Length));
}

#[test]
fn consumed() {
    let mut der = Der::new(&[2, 1, 5, 4, 0]);
    assert_eq!(der.expect(4), Err(Flaw::Tag));
    assert_eq!(der.expect(4), Ok(&[][..]));
    assert!(der.done());
}

#[test]
fn optional() {
    let mut der = Der::new(&[0xa0, 1, 9, 2, 1, 5]);
    assert_eq!(der.optional(2), Ok(None));
    assert_eq!(der.optional(0xa0), Ok(Some(&[9][..])));
    assert_eq!(der.optional(0xa0), Ok(None));
    assert_eq!(der.optional(2), Ok(Some(&[5][..])));
    assert_eq!(der.optional(2), Ok(None));
    assert_eq!(Der::new(&[2, 5, 1]).optional(2), Err(Flaw::Length));
}

#[test]
fn finish() {
    assert_eq!(Der::new(&[]).finish(), Ok(()));
    assert_eq!(Der::new(&[0]).finish(), Err(Flaw::Trailing));
}

#[test]
fn integers() {
    assert_eq!(integer(&[]), Err(Flaw::Value));
    assert_eq!(integer(&[0]), Ok(&[0][..]));
    assert_eq!(integer(&[0xff]), Ok(&[0xff][..]));
    assert_eq!(integer(&[0x7f]), Ok(&[0x7f][..]));
    assert_eq!(integer(&[0, 0x80]), Ok(&[0, 0x80][..]));
    assert_eq!(integer(&[0xff, 0x7f]), Ok(&[0xff, 0x7f][..]));
    assert_eq!(integer(&[0, 1]), Err(Flaw::Minimal));
    assert_eq!(integer(&[0, 0x7f]), Err(Flaw::Minimal));
    assert_eq!(integer(&[0, 0]), Err(Flaw::Minimal));
    assert_eq!(integer(&[0xff, 0x80]), Err(Flaw::Minimal));
    assert_eq!(integer(&[0xff, 0xff]), Err(Flaw::Minimal));
}

#[test]
fn natural() {
    assert_eq!(unsigned(&[0]), Ok(0));
    assert_eq!(unsigned(&[0x7f]), Ok(127));
    assert_eq!(unsigned(&[0, 0xff]), Ok(255));
    assert_eq!(unsigned(&[1, 0]), Ok(256));
    assert_eq!(unsigned(&[1; 8]), Ok(0x0101_0101_0101_0101));
    assert_eq!(
        unsigned(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Ok(u64::MAX)
    );
    assert_eq!(unsigned(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Flaw::Value));
    assert_eq!(unsigned(&[0x80]), Err(Flaw::Value));
    assert_eq!(unsigned(&[0xff]), Err(Flaw::Value));
    assert_eq!(unsigned(&[0, 0, 1]), Err(Flaw::Minimal));
    assert_eq!(unsigned(&[]), Err(Flaw::Value));
}

#[test]
fn booleans() {
    assert_eq!(boolean(&[0]), Ok(false));
    assert_eq!(boolean(&[0xff]), Ok(true));
    assert_eq!(boolean(&[1]), Err(Flaw::Value));
    assert_eq!(boolean(&[0x80]), Err(Flaw::Value));
    assert_eq!(boolean(&[]), Err(Flaw::Value));
    assert_eq!(boolean(&[0, 0]), Err(Flaw::Value));
    assert_eq!(boolean(&[0xff, 0xff]), Err(Flaw::Value));
}

#[test]
fn strings() {
    assert_eq!(bits(&[0]), Ok((0, &[][..])));
    assert_eq!(bits(&[0, 0xff, 0xaa]), Ok((0, &[0xff, 0xaa][..])));
    assert_eq!(bits(&[7, 0x80]), Ok((7, &[0x80][..])));
    assert_eq!(bits(&[4, 0xf0]), Ok((4, &[0xf0][..])));
    assert_eq!(bits(&[1, 0x02]), Ok((1, &[0x02][..])));
    assert_eq!(bits(&[]), Err(Flaw::Value));
    assert_eq!(bits(&[1]), Err(Flaw::Value));
    assert_eq!(bits(&[7]), Err(Flaw::Value));
    assert_eq!(bits(&[8, 0xff]), Err(Flaw::Value));
    assert_eq!(bits(&[0xff, 0]), Err(Flaw::Value));
    assert_eq!(bits(&[7, 0x81]), Err(Flaw::Value));
    assert_eq!(bits(&[1, 0x01]), Err(Flaw::Value));
    assert_eq!(bits(&[4, 0xf8]), Err(Flaw::Value));
    assert_eq!(bits(&[2, 0x0f, 0x05]), Err(Flaw::Value));
    assert_eq!(bits(&[2, 0xff, 0x04]), Ok((2, &[0xff, 0x04][..])));
}

#[test]
fn zeroes() {
    let wire = [&[0x30u8, 0x80][..], &[0u8; 128]].concat();
    assert_eq!(read(&wire), Err(Flaw::Length));
}

#[test]
fn fourbytes() {
    let wire = [&[4u8, 0x84, 1, 0, 0, 0][..], &vec![0u8; 1 << 24]].concat();
    assert_eq!(read(&wire).unwrap().1.len(), 1 << 24);
}

#[test]
fn masked() {
    assert_eq!(read(&[4, 0xc1, 5, 0]), Err(Flaw::Length));
    assert_eq!(read(&[4, 0x81 | 0x40, 5, 0]), Err(Flaw::Length));
    assert_eq!(read(&[4, 0xff, 5, 0]), Err(Flaw::Length));
}
