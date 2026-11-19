mod address;
mod read;
mod write;

use crate::error::Error;
use crate::field::Cursor;
use crate::frame::Direction;

pub use address::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
    Uni,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Original(Vec<u8>),
    Idle(u64),
    Reset([u8; 16]),
    Payload(u64),
    Data(u64),
    Window(Side, u64),
    Streams(Direction, u64),
    Exponent(u64),
    Delay(u64),
    Migration,
    Address(Address),
    Limit(u64),
    Source(Vec<u8>),
    Retry(Vec<u8>),
    Other(u64, Vec<u8>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    pub list: Vec<Param>,
}

impl Params {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Cursor::new(bytes);
        let mut list: Vec<Param> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        while reader.left() > 0 {
            let id = reader.big()?;
            if seen.contains(&id) {
                return Err(Error::Duplicate);
            }
            seen.push(id);
            let size = reader.big()?;
            let size = usize::try_from(size).map_err(|_| wire::Error::Truncated)?;
            let value = reader.take(size)?;
            list.push(Param::read(id, value)?);
        }
        Ok(Self { list })
    }
}
