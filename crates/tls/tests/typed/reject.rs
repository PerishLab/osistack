use crate::support::*;
use tls::{Error, Place, Typed};

fn fails(kind: u16, text: &str, place: Place, error: Error) {
    assert_eq!(
        Typed::parse(&extension(kind, text), place),
        Err(error),
        "{kind} {text}"
    );
}

fn good(kind: u16, text: &str, place: Place) -> Typed {
    Typed::parse(&extension(kind, text), place)
        .unwrap()
        .unwrap()
}

fn cut() -> Error {
    Error::Wire(wire::Error::Truncated)
}

const BINDER: &str = "20abababababababababababababababababababababababababababababababab";

fn offer(identities: &str, binders: &str) -> String {
    let first = identities.replace(' ', "").len() / 2;
    let second = binders.replace(' ', "").len() / 2;
    format!("{first:04x} {identities} {second:04x} {binders}")
}

#[test]
fn names() {
    let place = Place::Offer;
    fails(0, "0000", place, Error::Length);
    fails(0, "", place, cut());
    fails(0, "0004 01 0001 61", place, Error::Value);
    fails(0, "0003 00 0000", place, Error::Length);
    fails(0, "0008 00 0001 61 00 0001 62", place, Error::Duplicate);
    fails(0, "0002 0000", place, Error::Length);
    fails(0, "0004 00 0005 61", place, Error::Length);
    fails(0, "0004 00 0001 61 ff", place, Error::Trailing);
    fails(0, "0004 00 0001", place, cut());
    assert_eq!(
        good(0, "0004 00 0001 61", place),
        Typed::Name(Some(vec![0x61]))
    );
    assert_eq!(good(0, "", Place::Encrypted), Typed::Name(None));
    fails(0, "00", Place::Encrypted, Error::Length);
}

#[test]
fn lists() {
    for kind in [10, 13] {
        fails(kind, "0000", Place::Offer, Error::Length);
        fails(kind, "0003 001d00", Place::Offer, Error::Length);
        fails(kind, "0002 001d ff", Place::Offer, Error::Trailing);
        fails(kind, "0004 001d", Place::Offer, cut());
        fails(kind, "", Place::Offer, cut());
    }
    assert_eq!(
        good(10, "0004 001d 0017", Place::Encrypted),
        Typed::Groups(vec![0x1d, 0x17])
    );
    assert_eq!(
        good(13, "0002 0403", Place::Request),
        Typed::Algorithms(vec![0x0403])
    );
}

#[test]
fn protocols() {
    fails(16, "0000", Place::Offer, Error::Length);
    fails(16, "0001 00", Place::Offer, Error::Length);
    fails(16, "0003 05 6162", Place::Offer, Error::Length);
    fails(16, "0003 02 6162 ff", Place::Offer, Error::Trailing);
    fails(16, "0006 02 6162 02 6364", Place::Encrypted, Error::Value);
    fails(16, "0001 00", Place::Encrypted, Error::Length);
    fails(16, "0000", Place::Encrypted, Error::Length);
    let two = good(16, "0006 02 6162 02 6364", Place::Offer);
    assert_eq!(
        two,
        Typed::Protocols(vec![vec![0x61, 0x62], vec![0x63, 0x64]])
    );
    let one = good(16, "0003 02 6162", Place::Encrypted);
    assert_eq!(one, Typed::Protocols(vec![vec![0x61, 0x62]]));
}

#[test]
fn identities() {
    let one = "0001 61 00000001";
    let place = Place::Offer;
    assert!(matches!(
        good(41, &offer(one, BINDER), place),
        Typed::Offered { .. }
    ));
    fails(41, &offer("0001 61 000000", BINDER), place, Error::Length);
    fails(
        41,
        &offer(one, &BINDER[..BINDER.len() - 2]),
        place,
        Error::Length,
    );
    fails(
        41,
        &offer(
            "0000 00000001 0001 61 00000002",
            &format!("{BINDER}{BINDER}"),
        ),
        place,
        Error::Length,
    );
    fails(
        41,
        &format!("{} ff", offer(one, BINDER)),
        place,
        Error::Trailing,
    );
    fails(41, "0000 0000", place, Error::Length);
    fails(41, &offer("", BINDER), place, Error::Length);
    fails(41, &offer(one, ""), place, Error::Length);
    fails(41, "0007 0001", place, cut());
    fails(41, "", place, cut());
}

#[test]
fn binders() {
    let two = "0001 61 00000001 0001 62 00000002";
    let short = format!("1f{} {BINDER}", "ab".repeat(31));
    fails(41, &offer(two, &short), Place::Offer, Error::Length);
    fails(41, &offer(two, BINDER), Place::Offer, Error::Value);
    let one = "0001 61 00000001";
    fails(
        41,
        &offer(one, &format!("{BINDER}{BINDER}")),
        Place::Offer,
        Error::Value,
    );
    fails(
        41,
        &offer(one, &format!("{BINDER} 05")),
        Place::Offer,
        Error::Length,
    );
}

#[test]
fn selected() {
    assert_eq!(good(41, "0003", Place::Reply), Typed::Selected(3));
    fails(41, "00", Place::Reply, cut());
    fails(41, "000000", Place::Reply, Error::Trailing);
}

#[test]
fn early() {
    assert_eq!(good(42, "", Place::Offer), Typed::Early(None));
    fails(42, "00", Place::Offer, Error::Length);
    fails(42, "ff", Place::Encrypted, Error::Length);
    assert_eq!(
        good(42, "00000400", Place::Ticket),
        Typed::Early(Some(1024))
    );
    fails(42, "000004", Place::Ticket, cut());
    fails(42, "0000040000", Place::Ticket, Error::Trailing);
    fails(42, "", Place::Ticket, cut());
}

#[test]
fn versions() {
    fails(43, "00", Place::Offer, Error::Length);
    fails(43, "03 030403", Place::Offer, Error::Length);
    fails(43, "02 0304 ff", Place::Offer, Error::Trailing);
    fails(43, "04 0304", Place::Offer, cut());
    fails(43, "", Place::Offer, cut());
    assert_eq!(
        good(43, "04 0304 0303", Place::Offer),
        Typed::Versions(vec![0x0304, 0x0303])
    );
    for place in [Place::Reply, Place::Retry] {
        fails(43, "03", place, cut());
        fails(43, "030400", place, Error::Trailing);
        assert_eq!(good(43, "0304", place), Typed::Version(0x0304));
    }
}

#[test]
fn wrapped() {
    fails(44, "0000", Place::Offer, Error::Length);
    fails(44, "0001 aa ff", Place::Retry, Error::Trailing);
    fails(44, "0002 aa", Place::Offer, cut());
    fails(45, "00", Place::Offer, Error::Length);
    fails(45, "01 01 ff", Place::Offer, Error::Trailing);
    fails(45, "02 01", Place::Offer, cut());
    assert_eq!(
        good(44, "0002 aabb", Place::Retry),
        Typed::Cookie(vec![0xaa, 0xbb])
    );
    assert_eq!(
        good(45, "03 000102", Place::Offer),
        Typed::Modes(vec![0, 1, 2])
    );
}

#[test]
fn shares() {
    let place = Place::Offer;
    fails(51, "000a 001d0001aa 001d0001bb", place, Error::Duplicate);
    fails(51, "0004 001d 0000", place, Error::Length);
    fails(51, "0003 001d00", place, Error::Length);
    fails(51, "0005 001d0001aa ff", place, Error::Trailing);
    fails(51, "0007 001d0001aa", place, cut());
    assert_eq!(good(51, "0000", place), Typed::Shares(vec![]));
    let found = good(51, "000a 001d0001aa 00170001bb", place);
    assert!(matches!(found, Typed::Shares(items) if items.len() == 2));
}

#[test]
fn chosen() {
    fails(51, "001d 0001 aa ff", Place::Reply, Error::Trailing);
    fails(51, "001d 0000", Place::Reply, Error::Length);
    fails(51, "001d", Place::Reply, cut());
    fails(51, "00", Place::Retry, cut());
    fails(51, "001d00", Place::Retry, Error::Trailing);
    assert_eq!(good(51, "0017", Place::Retry), Typed::Group(0x17));
}

#[test]
fn prefixes() {
    let samples = [
        (0, "0004 00 0001 61", Place::Offer),
        (10, "0004 001d 0017", Place::Offer),
        (13, "0004 0403 0503", Place::Request),
        (16, "0006 02 6162 02 6364", Place::Offer),
        (41, &offer("0001 61 00000001", BINDER), Place::Offer),
        (41, "0003", Place::Reply),
        (42, "00000400", Place::Ticket),
        (43, "04 0304 0303", Place::Offer),
        (43, "0304", Place::Reply),
        (44, "0002 aabb", Place::Retry),
        (45, "02 0001", Place::Offer),
        (51, "000a 001d0001aa 00170001bb", Place::Offer),
        (51, "001d 0001 aa", Place::Reply),
        (51, "0017", Place::Retry),
    ];
    for (kind, text, place) in samples {
        let bytes = hex(text);
        assert!(
            Typed::parse(&extension(kind, text), place)
                .unwrap()
                .is_some()
        );
        for size in 0..bytes.len() {
            let part = tls::Extension {
                kind,
                data: bytes[..size].to_vec(),
            };
            assert!(Typed::parse(&part, place).is_err(), "{kind} {size}");
        }
    }
}
