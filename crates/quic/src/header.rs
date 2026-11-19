use crate::VERSION;
use crate::error::Error;
use crate::ident;
use crate::long::{Kind, Long};
use crate::negotiation::Negotiation;
use crate::retry::Retry;
use crate::short::Short;
use wire::Reader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Long(Long),
    Short(Short),
    Retry(Retry),
    Negotiation(Negotiation),
}

impl Header {
    pub fn parse(data: &[u8], local: usize) -> Result<Self, Error> {
        let mut reader = Reader::new(data);
        let first = reader.byte()?;
        if first & 0x80 == 0 {
            return Short::parse(first, &mut reader, local).map(Header::Short);
        }
        let version = ident::word(&mut reader)?;
        if version == 0 {
            return Negotiation::parse(first, &mut reader).map(Header::Negotiation);
        }
        if version != VERSION {
            return Err(Error::Version);
        }
        if first & 0x40 == 0 {
            return Err(Error::Fixed);
        }
        Self::long(first, &mut reader)
    }

    fn long(first: u8, reader: &mut Reader) -> Result<Self, Error> {
        match (first >> 4) & 3 {
            0 => Long::parse(Kind::Initial, reader).map(Header::Long),
            1 => Err(Error::Excluded),
            2 => Long::parse(Kind::Handshake, reader).map(Header::Long),
            _ => Retry::parse(first, reader).map(Header::Retry),
        }
    }
}
