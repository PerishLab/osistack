use crate::error::Error;
use crate::field;
use wire::{Reader, Writer};

pub const LIMIT: usize = 16384 + 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Change,
    Alert,
    Handshake,
    Application,
}

impl Content {
    fn code(self) -> u8 {
        match self {
            Content::Change => 20,
            Content::Alert => 21,
            Content::Handshake => 22,
            Content::Application => 23,
        }
    }

    fn of(code: u8) -> Result<Self, Error> {
        match code {
            20 => Ok(Content::Change),
            21 => Ok(Content::Alert),
            22 => Ok(Content::Handshake),
            23 => Ok(Content::Application),
            _ => Err(Error::Kind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub content: Content,
    pub version: u16,
    pub fragment: Vec<u8>,
}

impl Record {
    pub fn parse(data: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        if data.len() < 5 {
            return Self::early(data);
        }
        let mut reader = Reader::new(data);
        let content = Content::of(reader.byte()?)?;
        let version = field::short(&mut reader)?;
        let length = usize::from(field::short(&mut reader)?);
        if length > LIMIT {
            return Err(Error::Length);
        }
        if reader.left() < length {
            return Ok(None);
        }
        let fragment = reader.take(length)?.to_vec();
        Ok(Some((
            Self {
                content,
                version,
                fragment,
            },
            reader.at(),
        )))
    }

    fn early(data: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        if let Some(first) = data.first() {
            Content::of(*first)?;
        }
        Ok(None)
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        if self.fragment.len() > LIMIT {
            return Err(Error::Length);
        }
        let mut writer = Writer::new();
        writer.byte(self.content.code());
        writer.put(&self.version.to_be_bytes());
        writer.put(&(self.fragment.len() as u16).to_be_bytes());
        writer.put(&self.fragment);
        Ok(writer.finish())
    }
}
