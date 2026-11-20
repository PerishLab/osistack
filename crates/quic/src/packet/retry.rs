use crate::VERSION;
use crate::error::Error;
use crate::packet::ident::{self, LIMIT};
use crypto::Aead;
use wire::{Reader, Writer};

const TAG: usize = 16;
const KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

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

    pub fn fill(&mut self, odcid: &[u8]) -> Result<(), Error> {
        let mut empty = [];
        self.tag = Aead::Aes128
            .cipher(&KEY)?
            .seal(&NONCE, &self.pseudo(odcid)?, &mut empty)?;
        Ok(())
    }

    pub fn check(&self, odcid: &[u8]) -> Result<(), Error> {
        let mut empty = [];
        Aead::Aes128
            .cipher(&KEY)?
            .open(&NONCE, &self.pseudo(odcid)?, &mut empty, &self.tag)?;
        Ok(())
    }

    fn pseudo(&self, odcid: &[u8]) -> Result<Vec<u8>, Error> {
        if odcid.len() > LIMIT {
            return Err(Error::Length);
        }
        let packet = self.write()?;
        let end = packet.len().checked_sub(TAG).ok_or(Error::Length)?;
        let mut out = Vec::new();
        out.push(odcid.len() as u8);
        out.extend_from_slice(odcid);
        out.extend_from_slice(&packet[..end]);
        Ok(out)
    }
}
