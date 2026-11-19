use crate::error::Error;
use crate::packet::ident::LIMIT;
use crate::packet::number::Number;
use wire::{Reader, Writer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Short {
    pub spin: bool,
    pub phase: bool,
    pub dcid: Vec<u8>,
    pub offset: usize,
}

impl Short {
    pub fn parse(first: u8, reader: &mut Reader, local: usize) -> Result<Self, Error> {
        if local > LIMIT {
            return Err(Error::Length);
        }
        if first & 0x40 == 0 {
            return Err(Error::Fixed);
        }
        let dcid = reader.take(local)?.to_vec();
        let offset = reader.at();
        if reader.left() == 0 {
            return Err(wire::Error::Truncated.into());
        }
        Ok(Self {
            spin: first & 0x20 != 0,
            phase: first & 0x04 != 0,
            dcid,
            offset,
        })
    }

    pub fn write(&self, number: &Number) -> Result<Vec<u8>, Error> {
        number.check()?;
        if self.dcid.len() > LIMIT {
            return Err(Error::Length);
        }
        let spin = u8::from(self.spin) << 5;
        let phase = u8::from(self.phase) << 2;
        let mut writer = Writer::new();
        writer.byte(0x40 | spin | phase | number.bits());
        writer.put(&self.dcid);
        writer.put(&number.bytes());
        Ok(writer.finish())
    }
}
