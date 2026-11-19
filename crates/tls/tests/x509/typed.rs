use crate::support::{ALT, BASIC, PURPOSE, Parts, USAGE, flaw, oid, seq, single, tlv};
use tls::x509::{Basic, Flaw, General};

fn names(items: &[Vec<u8>]) -> Result<Option<Vec<General>>, Flaw> {
    let refs: Vec<&[u8]> = items.iter().map(|each| each.as_slice()).collect();
    let parts = single(ALT, None, &seq(&refs));
    parts.parse().map(|cert| cert.alt)
}

fn basic(value: &[u8]) -> Result<Option<Basic>, Flaw> {
    single(BASIC, None, value).parse().map(|cert| cert.basic)
}

fn usage(value: &[u8]) -> Result<Option<u16>, Flaw> {
    single(USAGE, None, value).parse().map(|cert| cert.usage)
}

#[test]
fn general() {
    let items = [
        tlv(0x82, b"a.test"),
        tlv(0x81, b"x@a.test"),
        tlv(0x86, b"https://a.test"),
        tlv(0x87, &[10, 0, 0, 1]),
        tlv(0x87, &[0; 16]),
        tlv(0xa4, &[0x30, 0]),
        tlv(0x88, &[0x2a, 3]),
        tlv(0x80, &[1]),
    ];
    let want = vec![
        General::Dns("a.test".into()),
        General::Email("x@a.test".into()),
        General::Uri("https://a.test".into()),
        General::Ip(vec![10, 0, 0, 1]),
        General::Ip(vec![0; 16]),
        General::Other(0xa4, vec![0x30, 0]),
        General::Other(0x88, vec![0x2a, 3]),
        General::Other(0x80, vec![1]),
    ];
    assert_eq!(names(&items), Ok(Some(want)));
}

#[test]
fn address() {
    for size in [0, 1, 3, 5, 8, 15, 17, 32] {
        assert_eq!(
            names(&[tlv(0x87, &vec![1; size])]),
            Err(Flaw::Value),
            "{size}"
        );
    }
}

#[test]
fn ascii() {
    for tag in [0x82, 0x81, 0x86] {
        assert_eq!(names(&[tlv(tag, "é".as_bytes())]), Err(Flaw::Value));
        assert_eq!(names(&[tlv(tag, &[0x80])]), Err(Flaw::Value));
        assert!(names(&[tlv(tag, &[0x7f])]).is_ok());
    }
}

#[test]
fn nothing() {
    assert_eq!(names(&[]), Err(Flaw::Value));
    let loose = single(ALT, None, &[0x04, 0]);
    assert_eq!(flaw(&loose), Flaw::Tag);
    let more = single(
        ALT,
        None,
        &[&seq(&[&tlv(0x82, b"a")])[..], &[5, 0]].concat(),
    );
    assert_eq!(flaw(&more), Flaw::Trailing);
    let cut = single(ALT, None, &[0x30, 0x04, 0x82, 0x09, 0x61]);
    assert_eq!(flaw(&cut), Flaw::Length);
}

#[test]
fn flags() {
    assert_eq!(
        basic(&[0x30, 0]),
        Ok(Some(Basic {
            ca: false,
            depth: None
        }))
    );
    let ca = basic(&[0x30, 3, 1, 1, 0xff]);
    assert_eq!(
        ca,
        Ok(Some(Basic {
            ca: true,
            depth: None
        }))
    );
    let deep = basic(&[0x30, 6, 1, 1, 0xff, 2, 1, 5]);
    assert_eq!(
        deep,
        Ok(Some(Basic {
            ca: true,
            depth: Some(5)
        }))
    );
    let bare = basic(&[0x30, 3, 2, 1, 5]);
    assert_eq!(
        bare,
        Ok(Some(Basic {
            ca: false,
            depth: Some(5)
        }))
    );
    let zero = basic(&[0x30, 6, 1, 1, 0xff, 2, 1, 0]);
    assert_eq!(
        zero,
        Ok(Some(Basic {
            ca: true,
            depth: Some(0)
        }))
    );
}

#[test]
fn depths() {
    assert_eq!(basic(&[0x30, 3, 1, 1, 0]), Err(Flaw::Value));
    assert_eq!(basic(&[0x30, 3, 1, 1, 1]), Err(Flaw::Value));
    assert_eq!(basic(&[0x30, 3, 2, 1, 0xff]), Err(Flaw::Value));
    assert_eq!(basic(&[0x30, 4, 2, 2, 0, 5]), Err(Flaw::Minimal));
    assert_eq!(basic(&[0x30, 5, 1, 1, 0xff, 5, 0]), Err(Flaw::Trailing));
    assert_eq!(basic(&[0x30, 3, 2, 1, 5, 0]), Err(Flaw::Trailing));
    let wide = [0x30, 11, 2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(basic(&wide), Err(Flaw::Value));
    let max = [0x30, 11, 2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255];
    assert_eq!(
        basic(&max),
        Ok(Some(Basic {
            ca: false,
            depth: Some(u64::MAX)
        }))
    );
    assert_eq!(basic(&[0x31, 0]), Err(Flaw::Tag));
    assert_eq!(basic(&[]), Err(Flaw::Length));
}

#[test]
fn critical() {
    let parts = single(BASIC, Some(true), &[0x30, 0]);
    assert!(parts.parse().unwrap().extensions[0].critical);
    let rest = single(&[0x2b, 6, 1], Some(true), &[9, 9, 9])
        .parse()
        .unwrap();
    assert_eq!(rest.extensions[0].value, [9, 9, 9]);
    assert!(rest.alt.is_none());
    assert!(rest.basic.is_none());
    assert!(rest.usage.is_none());
    assert!(rest.purposes.is_none());
    let both = Parts::with(&[
        crate::support::extension(BASIC, None, &[0x30, 0]),
        crate::support::extension(USAGE, None, &[3, 2, 7, 0x80]),
    ]);
    let cert = both.parse().unwrap();
    assert_eq!((cert.basic.is_some(), cert.usage), (true, Some(1)));
    assert_eq!(cert.extensions[0].value, [0x30, 0]);
}

#[test]
fn named() {
    assert_eq!(usage(&[3, 2, 7, 0x80]), Ok(Some(1)));
    assert_eq!(usage(&[3, 2, 5, 0xa0]), Ok(Some(5)));
    assert_eq!(usage(&[3, 2, 1, 0x06]), Ok(Some(0x60)));
    assert_eq!(usage(&[3, 2, 0, 0x01]), Ok(Some(0x80)));
    assert_eq!(usage(&[3, 2, 0, 0xff]), Ok(Some(0xff)));
    assert_eq!(usage(&[3, 3, 7, 0xff, 0x80]), Ok(Some(0x1ff)));
    assert_eq!(usage(&[3, 3, 7, 0x00, 0x80]), Ok(Some(0x100)));
    assert_eq!(usage(&[3, 3, 0, 0x80, 0x00]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 3, 7, 0x00, 0x00]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 3, 0, 0x00, 0x40]), Err(Flaw::Value));
}

#[test]
fn unnamed() {
    assert_eq!(usage(&[3, 3, 6, 0xff, 0xc0]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 4, 0, 0xff, 0xff, 0xff]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 2, 7, 0x00]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 2, 0, 0x00]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 1, 0]), Err(Flaw::Value));
    assert_eq!(usage(&[3, 2, 7, 0x81]), Err(Flaw::Value));
    assert_eq!(usage(&[4, 2, 7, 0x80]), Err(Flaw::Tag));
    assert_eq!(usage(&[3, 2, 7, 0x80, 5, 0]), Err(Flaw::Trailing));
    assert_eq!(usage(&[3, 0]), Err(Flaw::Value));
}

fn purposes(items: &[Vec<u8>]) -> Result<Option<Vec<String>>, Flaw> {
    let refs: Vec<&[u8]> = items.iter().map(|each| each.as_slice()).collect();
    let parts = single(PURPOSE, None, &seq(&refs));
    let cert = parts.parse()?;
    Ok(cert
        .purposes
        .map(|all| all.iter().map(|id| id.to_string()).collect()))
}

#[test]
fn purpose() {
    let server = oid(&[0x2b, 6, 1, 5, 5, 7, 3, 1]);
    let any = oid(&[0x55, 0x1d, 0x25, 0x00]);
    let want = Some(vec![
        "1.3.6.1.5.5.7.3.1".to_string(),
        "2.5.29.37.0".to_string(),
    ]);
    assert_eq!(purposes(&[server.clone(), any]), Ok(want));
    assert_eq!(
        purposes(std::slice::from_ref(&server))
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(purposes(&[]), Err(Flaw::Value));
    assert_eq!(purposes(&[tlv(4, &[1])]), Err(Flaw::Tag));
    assert_eq!(purposes(&[tlv(6, &[0x2b, 0x86])]), Err(Flaw::Value));
    assert_eq!(purposes(&[server, tlv(6, &[])]), Err(Flaw::Value));
}

#[test]
fn leftover() {
    let server = oid(&[0x2b, 6, 1, 5, 5, 7, 3, 1]);
    let more = [seq(&[&server]), vec![5, 0]].concat();
    let parts = single(PURPOSE, None, &more);
    assert_eq!(flaw(&parts), Flaw::Trailing);
}
