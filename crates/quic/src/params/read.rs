use super::{Address, Param, Side};
use crate::error::Error;
use crate::field::{Cursor, STREAMS, within};
use crate::frame::Direction;

impl Param {
    pub fn read(id: u64, value: &[u8]) -> Result<Self, Error> {
        Ok(match id {
            0x00 => Param::Original(Self::ident(value)?),
            0x02 => Param::Reset(Self::token(value)?),
            0x0c if value.is_empty() => Param::Migration,
            0x0c => return Err(Error::Length),
            0x0d => Param::Address(Address::read(value)?),
            0x0f => Param::Source(Self::ident(value)?),
            0x10 => Param::Retry(Self::ident(value)?),
            0x01 | 0x03..=0x0b | 0x0e => Self::number(id, Self::integer(value)?)?,
            _ => Param::Other(id, value.to_vec()),
        })
    }

    fn number(id: u64, value: u64) -> Result<Self, Error> {
        Ok(match id {
            0x01 => Param::Idle(value),
            0x03 if value < 1200 => return Err(Error::Value),
            0x03 => Param::Payload(value),
            0x04 => Param::Data(value),
            0x05 => Param::Window(Side::Local, value),
            0x06 => Param::Window(Side::Remote, value),
            0x07 => Param::Window(Side::Uni, value),
            0x08 => Param::Streams(Direction::Bidi, within(value, STREAMS)?),
            0x09 => Param::Streams(Direction::Uni, within(value, STREAMS)?),
            0x0a => Param::Exponent(within(value, 20)?),
            0x0b if value >= 1 << 14 => return Err(Error::Value),
            0x0b => Param::Delay(value),
            _ if value < 2 => return Err(Error::Value),
            _ => Param::Limit(value),
        })
    }

    fn integer(value: &[u8]) -> Result<u64, Error> {
        let mut reader = Cursor::new(value);
        let number = reader.varint().map_err(|_| Error::Length)?.get();
        if reader.left() > 0 {
            return Err(Error::Length);
        }
        Ok(number)
    }

    fn token(value: &[u8]) -> Result<[u8; 16], Error> {
        if value.len() != 16 {
            return Err(Error::Length);
        }
        let mut reader = Cursor::new(value);
        reader.array()
    }

    fn ident(value: &[u8]) -> Result<Vec<u8>, Error> {
        if value.len() > 20 {
            return Err(Error::Length);
        }
        Ok(value.to_vec())
    }
}
