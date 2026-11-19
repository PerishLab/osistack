use crate::error::Error;
use crate::extension::{self, Extension};
use crate::field;
use wire::{Reader, Writer};

pub const VERSION: u16 = 0x0303;
pub const SESSION: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub random: [u8; 32],
    pub session: Vec<u8>,
    pub suites: Vec<u16>,
    pub extensions: Vec<Extension>,
}

impl Offer {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(body);
        if field::short(&mut reader)? != VERSION {
            return Err(Error::Version);
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(reader.take(32)?);
        let session = field::prefixed(&mut reader, 1)?;
        if session.len() > SESSION {
            return Err(Error::Length);
        }
        let suites = Self::suites(field::prefixed(&mut reader, 2)?)?;
        if field::prefixed(&mut reader, 1)? != [0] {
            return Err(Error::Compression);
        }
        let extensions = extension::parse(&mut reader, 8)?;
        if reader.left() > 0 {
            return Err(Error::Trailing);
        }
        Ok(Self {
            random,
            session: session.to_vec(),
            suites,
            extensions,
        })
    }

    fn suites(raw: &[u8]) -> Result<Vec<u16>, Error> {
        if raw.is_empty() || !raw.len().is_multiple_of(2) {
            return Err(Error::Suites);
        }
        Ok(raw
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect())
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        if self.session.len() > SESSION {
            return Err(Error::Length);
        }
        if self.suites.is_empty() {
            return Err(Error::Suites);
        }
        let mut writer = Writer::new();
        writer.put(&VERSION.to_be_bytes());
        writer.put(&self.random);
        field::put(&mut writer, &self.session, 1)?;
        let suites: Vec<u8> = self
            .suites
            .iter()
            .flat_map(|suite| suite.to_be_bytes())
            .collect();
        field::put(&mut writer, &suites, 2)?;
        field::put(&mut writer, &[0], 1)?;
        extension::write(&mut writer, &self.extensions, 8)?;
        Ok(writer.finish())
    }
}
