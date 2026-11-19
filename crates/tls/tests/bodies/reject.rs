use crate::data::*;
use crate::support::*;
use tls::{Alert, Chain, Encrypted, End, Error, Finished, Kind, Request, Ticket, Update, Verify};

fn cut() -> Error {
    Error::Wire(wire::Error::Truncated)
}

fn stub(lifetime: &str, tail: &str) -> Vec<u8> {
    hex(&format!("{lifetime} 00000002 00 0001 aa {tail}"))
}

#[test]
fn extensions() {
    let dup = hex("0008 00010000 00010000");
    assert_eq!(Encrypted::parse(&dup), Err(Error::Duplicate));
    assert_eq!(
        Chain::parse(&hex("00 00000e 000001aa 0008 00010000 00010000")),
        Err(Error::Duplicate)
    );
    assert_eq!(
        Request::parse(&hex("00 000c 000d00020403 000d00020403")),
        Err(Error::Duplicate)
    );
    assert_eq!(
        Ticket::parse(&stub("00000001", "0008 00010000 00010000")),
        Err(Error::Duplicate)
    );
    let entry = hex("00 00000a 000001aa 0004 00010005");
    assert_eq!(Chain::parse(&entry), Err(Error::Length));
    assert_eq!(Request::parse(&hex("00 0004 00010005")), Err(Error::Length));
    let over = hex("0004 00010005");
    assert_eq!(Encrypted::parse(&over), Err(Error::Length));
    assert_eq!(
        Ticket::parse(&stub("00000001", "0004 00010005")),
        Err(Error::Length)
    );
}

#[test]
fn encrypted() {
    assert_eq!(Encrypted::parse(&hex("0000")).unwrap().extensions, vec![]);
    assert_eq!(Encrypted::parse(&hex("0000 ff")), Err(Error::Trailing));
    assert_eq!(
        Encrypted::parse(&hex("0004 00010000 00")),
        Err(Error::Trailing)
    );
    for text in ["", "00", "0004 0001"] {
        assert_eq!(Encrypted::parse(&hex(text)), Err(cut()), "{text}");
    }
}

#[test]
fn entries() {
    assert_eq!(
        Chain::parse(&hex("00 000005 000000 0000")),
        Err(Error::Length)
    );
    assert_eq!(Chain::parse(&hex("00 000002 0001")), Err(Error::Length));
    assert_eq!(
        Chain::parse(&hex("00 000004 000001 aa")),
        Err(Error::Length)
    );
    assert_eq!(Chain::parse(&hex("00 000000 ff")), Err(Error::Trailing));
    let empty = Chain::parse(&hex("00 000000")).unwrap();
    assert_eq!((empty.context.len(), empty.entries.len()), (0, 0));
    let context = Chain::parse(&hex("02 aabb 000006 000001 aa 0000")).unwrap();
    assert_eq!(context.context, vec![0xaa, 0xbb]);
    assert_eq!(context.entries[0].cert, vec![0xaa]);
    for text in ["", "00", "00 000001", "02 aa", "00 000005 000001"] {
        assert_eq!(Chain::parse(&hex(text)), Err(cut()), "{text}");
    }
}

#[test]
fn request() {
    assert_eq!(Request::parse(&hex("00 0000")), Err(Error::Length));
    assert_eq!(Request::parse(&hex("00 0001 00")), Err(Error::Length));
    assert_eq!(Request::parse(&hex("00 0002 000d")), Err(Error::Length));
    assert_eq!(
        Request::parse(&hex("00 0004 00010000")),
        Err(Error::Missing)
    );
    assert_eq!(
        Request::parse(&hex("00 0006 000d00020403 ff")),
        Err(Error::Trailing)
    );
    let found = Request::parse(&hex("01 aa 0006 000d00020403")).unwrap();
    assert_eq!(
        (found.context, kinds(&found.extensions)),
        (vec![0xaa], vec![13])
    );
    for text in ["", "00", "00 0006"] {
        assert_eq!(Request::parse(&hex(text)), Err(cut()), "{text}");
    }
}

#[test]
fn verify() {
    assert_eq!(Verify::parse(&hex("0804 0000")).unwrap().signature, vec![]);
    assert_eq!(Verify::parse(&hex("0804 0003 aa")), Err(cut()));
    assert_eq!(Verify::parse(&hex("0804 0000 ff")), Err(Error::Trailing));
    for text in ["", "08", "0804", "0804 00"] {
        assert_eq!(Verify::parse(&hex(text)), Err(cut()), "{text}");
    }
}

#[test]
fn finished() {
    let body = hex(&"ab".repeat(32));
    assert!(Finished::parse(&body, 32).is_ok());
    assert_eq!(Finished::parse(&body[1..], 32), Err(Error::Length));
    assert_eq!(
        Finished::parse(&[&body[..], &[0]].concat(), 32),
        Err(Error::Length)
    );
    assert_eq!(Finished::parse(&body, 48), Err(Error::Length));
    assert_eq!(Finished::parse(&[], 0).unwrap().data, vec![]);
}

#[test]
fn lifetime() {
    assert!(Ticket::parse(&stub("00093a80", "0000")).is_ok());
    assert_eq!(Ticket::parse(&stub("00093a81", "0000")), Err(Error::Value));
    assert_eq!(Ticket::parse(&stub("ffffffff", "0000")), Err(Error::Value));
}

#[test]
fn ticket() {
    let empty = hex("00000001 00000002 00 0000 0000");
    assert_eq!(Ticket::parse(&empty), Err(Error::Length));
    assert_eq!(
        Ticket::parse(&stub("00000001", "0000 ff")),
        Err(Error::Trailing)
    );
    for text in [
        "",
        "00000001",
        "00000001 00000002",
        "00000001 00000002 01",
        "00000001 00000002 00 0002 aa",
    ] {
        assert_eq!(Ticket::parse(&hex(text)), Err(cut()), "{text}");
    }
}

#[test]
fn update() {
    assert_eq!(
        Update::parse(&hex("00")).unwrap(),
        Update { request: false }
    );
    assert_eq!(Update::parse(&hex("01")).unwrap(), Update { request: true });
    assert_eq!(Update::parse(&hex("02")), Err(Error::Value));
    assert_eq!(Update::parse(&hex("ff")), Err(Error::Value));
    assert_eq!(Update::parse(&[]), Err(cut()));
    assert_eq!(Update::parse(&hex("01 00")), Err(Error::Trailing));
}

#[test]
fn early() {
    assert_eq!(End::parse(&hex("00")), Err(Error::Trailing));
    assert_eq!(End::parse(&hex("0000")), Err(Error::Trailing));
}

#[test]
fn alert() {
    assert_eq!(Alert::parse(&hex("01")), Err(cut()));
    assert_eq!(Alert::parse(&[]), Err(cut()));
    assert_eq!(Alert::parse(&hex("010000")), Err(Error::Trailing));
    let fatal = Alert::parse(&hex("0232")).unwrap();
    assert_eq!((fatal.level, fatal.description), (2, 0x32));
    let odd = Alert::parse(&hex("ffff")).unwrap();
    assert_eq!((odd.level, odd.description), (255, 255));
}

#[test]
fn prefixes() {
    let body = |text: &str, kind| unwrap(text, kind);
    let samples: Vec<(&str, Vec<u8>)> = vec![
        ("encrypted", body(ENCRYPTED[1], Kind::Extensions)),
        ("chain", body(CHAINS[1], Kind::Certificate)),
        ("request", body(REQUEST, Kind::Request)),
        ("verify", body(VERIFIES[2], Kind::Verify)),
        ("ticket", body(TICKET, Kind::Ticket)),
    ];
    for (name, bytes) in &samples {
        for size in 0..bytes.len() {
            let part = &bytes[..size];
            let failed = match *name {
                "encrypted" => Encrypted::parse(part).is_err(),
                "chain" => Chain::parse(part).is_err(),
                "request" => Request::parse(part).is_err(),
                "verify" => Verify::parse(part).is_err(),
                _ => Ticket::parse(part).is_err(),
            };
            assert!(failed, "{name} {size}");
        }
    }
}
