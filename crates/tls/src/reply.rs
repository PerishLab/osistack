use crate::error::Error;
use crate::extension::{self, Extension};
use crate::field;
use crate::offer::{SESSION, VERSION};
use wire::{Reader, Writer};

const RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub random: [u8; 32],
    pub session: Vec<u8>,
    pub suite: u16,
    pub extensions: Vec<Extension>,
}

impl Reply {
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
        let suite = field::short(&mut reader)?;
        if reader.byte()? != 0 {
            return Err(Error::Compression);
        }
        let extensions = extension::parse(&mut reader, 6)?;
        if reader.left() > 0 {
            return Err(Error::Trailing);
        }
        Ok(Self {
            random,
            session: session.to_vec(),
            suite,
            extensions,
        })
    }

    pub fn retry(&self) -> bool {
        self.random == RETRY
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        if self.session.len() > SESSION {
            return Err(Error::Length);
        }
        let mut writer = Writer::new();
        writer.put(&VERSION.to_be_bytes());
        writer.put(&self.random);
        field::put(&mut writer, &self.session, 1)?;
        writer.put(&self.suite.to_be_bytes());
        writer.byte(0);
        extension::write(&mut writer, &self.extensions, 6)?;
        Ok(writer.finish())
    }
}
