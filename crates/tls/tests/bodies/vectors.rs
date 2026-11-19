use crate::data::*;
use crate::support::*;
use tls::{Alert, Chain, Encrypted, End, Finished, Kind, Request, Ticket, Verify};

#[test]
fn encrypted() {
    let orders = [
        vec![0x0a, 0x1c, 0x00],
        vec![0x0a, 0x1c, 0x00, 0x2a],
        vec![0x0a, 0x1c, 0x00],
    ];
    for (text, order) in ENCRYPTED.iter().zip(orders) {
        let body = unwrap(text, Kind::Extensions);
        let found = Encrypted::parse(&body).unwrap();
        assert_eq!(kinds(&found.extensions), order);
        assert_eq!(found.write().unwrap(), body);
    }
    assert_eq!(unwrap(ENCRYPTED[0], Kind::Extensions).len(), 36);
    assert_eq!(unwrap(ENCRYPTED[1], Kind::Extensions).len(), 40);
    assert_eq!(unwrap(ENCRYPTED[2], Kind::Extensions).len(), 24);
}

#[test]
fn chains() {
    let sizes = [432, 306, 438];
    for (text, size) in CHAINS.iter().zip(sizes) {
        let body = unwrap(text, Kind::Certificate);
        let found = Chain::parse(&body).unwrap();
        assert!(found.context.is_empty());
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].cert.len(), size);
        assert!(found.entries[0].extensions.is_empty());
        assert_eq!(found.write().unwrap(), body);
    }
    assert_eq!(hex(CHAINS[0]).len(), 445);
    assert_eq!(hex(CHAINS[1]).len(), 319);
    assert_eq!(hex(CHAINS[2]).len(), 451);
}

#[test]
fn request() {
    let wire = hex(REQUEST);
    assert_eq!(wire.len(), 43);
    let body = unwrap(REQUEST, Kind::Request);
    let found = Request::parse(&body).unwrap();
    assert!(found.context.is_empty());
    assert_eq!(kinds(&found.extensions), vec![13]);
    assert_eq!(found.extensions[0].data.len(), 32);
    assert_eq!(found.write().unwrap(), body);
}

#[test]
fn verifies() {
    let shapes = [
        (0x0804, 128),
        (0x0804, 128),
        (0x0403, 71),
        (0x0804, 128),
        (0x0804, 128),
    ];
    assert_eq!(VERIFIES.len(), 5);
    for (text, (algorithm, size)) in VERIFIES.iter().zip(shapes) {
        let body = unwrap(text, Kind::Verify);
        let found = Verify::parse(&body).unwrap();
        assert_eq!((found.algorithm, found.signature.len()), (algorithm, size));
        assert_eq!(found.write().unwrap(), body);
    }
    assert_eq!(hex(VERIFIES[2]).len(), 79);
}

#[test]
fn finishes() {
    assert_eq!(FINISHES.len(), 10);
    for text in FINISHES {
        assert_eq!(hex(text).len(), 36);
        let body = unwrap(text, Kind::Finished);
        let found = Finished::parse(&body, 32).unwrap();
        assert_eq!(found.data, body);
        assert_eq!(found.write().unwrap(), body);
    }
}

#[test]
fn ticket() {
    let wire = hex(TICKET);
    assert_eq!(wire.len(), 205);
    let body = unwrap(TICKET, Kind::Ticket);
    let found = Ticket::parse(&body).unwrap();
    assert_eq!(found.lifetime, 30);
    assert_eq!(found.add, 0xfad6aac5);
    assert_eq!(found.nonce, vec![0, 0]);
    assert_eq!(found.ticket.len(), 178);
    assert_eq!(found.extensions, vec![extension(0x2a, &hex("00000400"))]);
    assert_eq!(found.write().unwrap(), body);
}

#[test]
fn early() {
    let body = unwrap(END, Kind::Early);
    assert!(body.is_empty());
    assert_eq!(End::parse(&body).unwrap(), End);
    assert_eq!(End.write().unwrap(), body);
}

#[test]
fn alert() {
    let bytes = hex("0100");
    let found = Alert::parse(&bytes).unwrap();
    assert_eq!((found.level, found.description), (1, 0));
    assert_eq!(found.write().unwrap(), bytes);
}
