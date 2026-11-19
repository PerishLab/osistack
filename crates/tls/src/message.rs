use crate::error::Error;
use wire::{Reader, Writer};

const MAXIMUM: usize = (1 << 24) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Offer,
    Reply,
    Ticket,
    Early,
    Extensions,
    Certificate,
    Request,
    Verify,
    Finished,
    Update,
    Hash,
}

impl Kind {
    fn code(self) -> u8 {
        match self {
            Kind::Offer => 1,
            Kind::Reply => 2,
            Kind::Ticket => 4,
            Kind::Early => 5,
            Kind::Extensions => 8,
            Kind::Certificate => 11,
            Kind::Request => 13,
            Kind::Verify => 15,
            Kind::Finished => 20,
            Kind::Update => 24,
            Kind::Hash => 254,
        }
    }

    fn of(code: u8) -> Result<Self, Error> {
        match code {
            1 => Ok(Kind::Offer),
            2 => Ok(Kind::Reply),
            4 => Ok(Kind::Ticket),
            5 => Ok(Kind::Early),
            8 => Ok(Kind::Extensions),
            11 => Ok(Kind::Certificate),
            13 => Ok(Kind::Request),
            15 => Ok(Kind::Verify),
            20 => Ok(Kind::Finished),
            24 => Ok(Kind::Update),
            254 => Ok(Kind::Hash),
            _ => Err(Error::Kind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub body: Vec<u8>,
}

impl Message {
    pub fn parse(data: &[u8], limit: usize) -> Result<Option<(Self, usize)>, Error> {
        let mut reader = Reader::new(data);
        let Ok(code) = reader.byte() else {
            return Ok(None);
        };
        let kind = Kind::of(code)?;
        let Ok(raw) = reader.take(3) else {
            return Ok(None);
        };
        let length = raw
            .iter()
            .fold(0usize, |acc, next| (acc << 8) | usize::from(*next));
        if length > limit {
            return Err(Error::Length);
        }
        if reader.left() < length {
            return Ok(None);
        }
        let body = reader.take(length)?.to_vec();
        Ok(Some((Self { kind, body }, reader.at())))
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        if self.body.len() > MAXIMUM {
            return Err(Error::Length);
        }
        let mut writer = Writer::new();
        writer.byte(self.kind.code());
        writer.put(&(self.body.len() as u32).to_be_bytes()[1..]);
        writer.put(&self.body);
        Ok(writer.finish())
    }
}
