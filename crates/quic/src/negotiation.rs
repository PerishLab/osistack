use crate::error::Error;
use crate::ident;
use wire::{Reader, Writer};

const LIMIT: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiation {
    pub unused: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub versions: Vec<u32>,
}

impl Negotiation {
    pub fn parse(first: u8, reader: &mut Reader) -> Result<Self, Error> {
        let dcid = ident::take(reader, LIMIT)?;
        let scid = ident::take(reader, LIMIT)?;
        if !reader.left().is_multiple_of(4) {
            return Err(Error::Versions);
        }
        let mut versions = Vec::new();
        while reader.left() > 0 {
            versions.push(ident::word(reader)?);
        }
        Ok(Self {
            unused: first & 0x7f,
            dcid,
            scid,
            versions,
        })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        writer.byte(0x80 | (self.unused & 0x7f));
        writer.put(&[0, 0, 0, 0]);
        ident::put(&mut writer, &self.dcid, LIMIT)?;
        ident::put(&mut writer, &self.scid, LIMIT)?;
        for version in &self.versions {
            writer.put(&version.to_be_bytes());
        }
        Ok(writer.finish())
    }
}
