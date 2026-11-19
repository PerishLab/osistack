use crate::VERSION;
use crate::error::Error;
use crate::packet::ident::{self, LIMIT};
use wire::{Reader, Writer};

const TAG: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    pub unused: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub tag: [u8; TAG],
}

impl Retry {
    pub fn parse(first: u8, reader: &mut Reader) -> Result<Self, Error> {
        let dcid = ident::take(reader, LIMIT)?;
        let scid = ident::take(reader, LIMIT)?;
        let size = reader
            .left()
            .checked_sub(TAG)
            .ok_or(wire::Error::Truncated)?;
        let token = reader.take(size)?.to_vec();
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(reader.take(TAG)?);
        Ok(Self {
            unused: first & 0x0f,
            dcid,
            scid,
            token,
            tag,
        })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        writer.byte(0xf0 | (self.unused & 0x0f));
        writer.put(&VERSION.to_be_bytes());
        ident::put(&mut writer, &self.dcid, LIMIT)?;
        ident::put(&mut writer, &self.scid, LIMIT)?;
        writer.put(&self.token);
        writer.put(&self.tag);
        Ok(writer.finish())
    }
}
