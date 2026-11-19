use crate::support::*;
use tls::{Error, Place, Typed};

const ALL: [Place; 6] = [
    Place::Offer,
    Place::Reply,
    Place::Retry,
    Place::Encrypted,
    Place::Ticket,
    Place::Request,
];

fn allowed(kind: u16) -> Vec<Place> {
    match kind {
        0 | 10 | 16 => vec![Place::Offer, Place::Encrypted],
        13 => vec![Place::Offer, Place::Request],
        41 => vec![Place::Offer, Place::Reply],
        42 => vec![Place::Offer, Place::Encrypted, Place::Ticket],
        43 | 51 => vec![Place::Offer, Place::Reply, Place::Retry],
        44 => vec![Place::Offer, Place::Retry],
        _ => vec![Place::Offer],
    }
}

#[test]
fn table() {
    for kind in [0, 10, 13, 16, 41, 42, 43, 44, 45, 51] {
        let empty = extension(kind, "");
        for place in ALL {
            let found = Typed::parse(&empty, place);
            if allowed(kind).contains(&place) {
                assert_ne!(found, Err(Error::Place), "{kind} {place:?}");
            } else {
                assert_eq!(found, Err(Error::Place), "{kind} {place:?}");
            }
        }
    }
}

#[test]
fn before() {
    let garbage = extension(45, "ffffff");
    assert_eq!(Typed::parse(&garbage, Place::Reply), Err(Error::Place));
    assert_eq!(Typed::parse(&garbage, Place::Ticket), Err(Error::Place));
}

#[test]
fn unknown() {
    for kind in [0xff01, 0x0023, 0x001c, 0x0039, 0x0005, 0xfe00, 0x002f] {
        let found = extension(kind, "0102");
        for place in ALL {
            assert_eq!(Typed::parse(&found, place), Ok(None), "{kind} {place:?}");
        }
    }
}
