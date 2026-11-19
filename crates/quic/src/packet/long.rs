use crate::VERSION;
use crate::error::Error;
use crate::packet::ident::{self, LIMIT};
use crate::packet::number::Number;
use wire::{Reader, Varint, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Initial,
    Handshake,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Long {
    pub kind: Kind,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub length: u64,
    pub offset: usize,
}

impl Long {
    pub fn parse(kind: Kind, reader: &mut Reader) -> Result<Self, Error> {
        let dcid = ident::take(reader, LIMIT)?;
        let scid = ident::take(reader, LIMIT)?;
        let token = match kind {
            Kind::Initial => {
                let size = reader.varint()?.get();
                let size = usize::try_from(size).map_err(|_| wire::Error::Truncated)?;
                reader.take(size)?.to_vec()
            }
            Kind::Handshake => Vec::new(),
        };
        let length = reader.varint()?.get();
        if length == 0 {
            return Err(Error::Length);
        }
        if length > reader.left() as u64 {
            return Err(wire::Error::Truncated.into());
        }
        let offset = reader.at();
        Ok(Self {
            kind,
            dcid,
            scid,
            token,
            length,
            offset,
        })
    }

    pub fn write(&self, number: &Number) -> Result<Vec<u8>, Error> {
        number.check()?;
        if self.length < number.length as u64 {
            return Err(Error::Length);
        }
        let mut writer = Writer::new();
        let kind = match self.kind {
            Kind::Initial => 0,
            Kind::Handshake => 2,
        };
        writer.byte(0xc0 | kind << 4 | number.bits());
        writer.put(&VERSION.to_be_bytes());
        ident::put(&mut writer, &self.dcid, LIMIT)?;
        ident::put(&mut writer, &self.scid, LIMIT)?;
        self.tokens(&mut writer)?;
        writer.varint(Varint::new(self.length)?);
        writer.put(&number.bytes());
        Ok(writer.finish())
    }

    fn tokens(&self, writer: &mut Writer) -> Result<(), Error> {
        match self.kind {
            Kind::Initial => {
                writer.varint(Varint::new(self.token.len() as u64)?);
                writer.put(&self.token);
            }
            Kind::Handshake if !self.token.is_empty() => return Err(Error::Token),
            Kind::Handshake => {}
        }
        Ok(())
    }
}
