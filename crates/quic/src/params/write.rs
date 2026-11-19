use super::{Param, Params, Side};
use crate::error::Error;
use crate::field::{STREAMS, pack, put, within};
use crate::frame::Direction;
use wire::Writer;

impl Params {
    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        let mut seen: Vec<u64> = Vec::new();
        for param in &self.list {
            let (id, value) = param.value()?;
            if seen.contains(&id) {
                return Err(Error::Duplicate);
            }
            seen.push(id);
            put(&mut writer, id)?;
            pack(&mut writer, &value)?;
        }
        Ok(writer.finish())
    }
}

impl Param {
    pub fn value(&self) -> Result<(u64, Vec<u8>), Error> {
        Ok(match self {
            Param::Original(bytes) => (0x00, Self::cids(bytes)?),
            Param::Reset(token) => (0x02, token.to_vec()),
            Param::Migration => (0x0c, Vec::new()),
            Param::Address(address) => (0x0d, address.write()?),
            Param::Source(bytes) => (0x0f, Self::cids(bytes)?),
            Param::Retry(bytes) => (0x10, Self::cids(bytes)?),
            Param::Other(id, _) if *id <= 0x10 => return Err(Error::Kind),
            Param::Other(id, bytes) => (*id, bytes.clone()),
            _ => self.scalar()?,
        })
    }

    fn scalar(&self) -> Result<(u64, Vec<u8>), Error> {
        let (id, value) = match self {
            Param::Idle(value) => (0x01, *value),
            Param::Payload(value) if *value < 1200 => return Err(Error::Value),
            Param::Payload(value) => (0x03, *value),
            Param::Data(value) => (0x04, *value),
            Param::Window(side, value) => (Self::side(*side), *value),
            Param::Streams(Direction::Bidi, value) => (0x08, within(*value, STREAMS)?),
            Param::Streams(Direction::Uni, value) => (0x09, within(*value, STREAMS)?),
            Param::Exponent(value) => (0x0a, within(*value, 20)?),
            Param::Delay(value) if *value >= 1 << 14 => return Err(Error::Value),
            Param::Delay(value) => (0x0b, *value),
            Param::Limit(value) if *value < 2 => return Err(Error::Value),
            Param::Limit(value) => (0x0e, *value),
            _ => return Err(Error::Kind),
        };
        let mut writer = Writer::new();
        put(&mut writer, value)?;
        Ok((id, writer.finish()))
    }

    fn side(side: Side) -> u64 {
        match side {
            Side::Local => 0x05,
            Side::Remote => 0x06,
            Side::Uni => 0x07,
        }
    }

    fn cids(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if bytes.len() > 20 {
            return Err(Error::Length);
        }
        Ok(bytes.to_vec())
    }
}
