mod read;
mod write;

use crate::error::Error;
use crate::extension::Extension;
use read::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Offer,
    Reply,
    Retry,
    Encrypted,
    Ticket,
    Request,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub group: u16,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub label: Vec<u8>,
    pub age: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Typed {
    Name(Option<Vec<u8>>),
    Groups(Vec<u16>),
    Algorithms(Vec<u16>),
    Protocols(Vec<Vec<u8>>),
    Offered {
        identities: Vec<Identity>,
        binders: Vec<Vec<u8>>,
    },
    Selected(u16),
    Early(Option<u32>),
    Versions(Vec<u16>),
    Version(u16),
    Cookie(Vec<u8>),
    Modes(Vec<u8>),
    Shares(Vec<Share>),
    Chosen(Share),
    Group(u16),
}

impl Place {
    fn of(kind: u16) -> Option<&'static [Place]> {
        use Place::*;
        Some(match kind {
            0 | 10 | 16 => &[Offer, Encrypted],
            13 => &[Offer, Request],
            41 => &[Offer, Reply],
            42 => &[Offer, Encrypted, Ticket],
            43 | 51 => &[Offer, Reply, Retry],
            44 => &[Offer, Retry],
            45 => &[Offer],
            _ => return None,
        })
    }
}

impl Typed {
    pub fn parse(extension: &Extension, place: Place) -> Result<Option<Typed>, Error> {
        let Some(places) = Place::of(extension.kind) else {
            return Ok(None);
        };
        if !places.contains(&place) {
            return Err(Error::Place);
        }
        Read::new(&extension.data, place)
            .typed(extension.kind)
            .map(Some)
    }
}
