use crate::error::Error;
use wire::{Huffman, Prefix, Reader, Writer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Name {
    Static(usize),
    Dynamic(u64),
    Literal(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Capacity(u64),
    Insert { name: Name, value: Vec<u8> },
    Duplicate(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    Acknowledge(u64),
    Cancel(u64),
    Increment(u64),
}

fn lead(input: &[u8], reader: &Reader) -> Result<u8, Error> {
    input
        .get(reader.at())
        .copied()
        .ok_or(Error::Wire(wire::Error::Truncated))
}

fn short(error: Error) -> Result<(), Error> {
    match error {
        Error::Wire(wire::Error::Truncated) => Ok(()),
        other => Err(other),
    }
}

impl Instruction {
    pub fn decode(input: &[u8], huffman: &Huffman) -> Result<Option<(Self, usize)>, Error> {
        let mut reader = Reader::new(input);
        match Self::read(input, &mut reader, huffman) {
            Ok(found) => Ok(Some((found, reader.at()))),
            Err(error) => short(error).map(|()| None),
        }
    }

    pub fn encode(&self, huffman: Option<&Huffman>) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        match self {
            Self::Capacity(value) => Self::integer(&mut writer, 5, 0x20, *value)?,
            Self::Duplicate(index) => Self::integer(&mut writer, 5, 0x00, *index)?,
            Self::Insert {
                name: Name::Static(index),
                value,
            } => {
                Self::integer(&mut writer, 6, 0xc0, *index as u64)?;
                Self::string(&mut writer, (7, 0x00), huffman, value)?;
            }
            Self::Insert {
                name: Name::Dynamic(index),
                value,
            } => {
                Self::integer(&mut writer, 6, 0x80, *index)?;
                Self::string(&mut writer, (7, 0x00), huffman, value)?;
            }
            Self::Insert {
                name: Name::Literal(name),
                value,
            } => {
                Self::string(&mut writer, (5, 0x40), huffman, name)?;
                Self::string(&mut writer, (7, 0x00), huffman, value)?;
            }
        }
        Ok(writer.finish())
    }

    fn read(input: &[u8], reader: &mut Reader, huffman: &Huffman) -> Result<Self, Error> {
        let lead = lead(input, reader)?;
        if lead & 0x80 != 0 {
            let prefixed = reader.prefixed(Prefix::new(6)?)?;
            let name = if prefixed.high & 0x40 != 0 {
                Name::Static(usize::try_from(prefixed.value).map_err(|_| Error::Index)?)
            } else {
                Name::Dynamic(prefixed.value)
            };
            let value = Self::text(reader, 7, 0x80, huffman)?;
            return Ok(Self::Insert { name, value });
        }
        if lead & 0x40 != 0 {
            let name = Self::text(reader, 5, 0x20, huffman)?;
            let value = Self::text(reader, 7, 0x80, huffman)?;
            return Ok(Self::Insert {
                name: Name::Literal(name),
                value,
            });
        }
        let prefixed = reader.prefixed(Prefix::new(5)?)?;
        Ok(if lead & 0x20 != 0 {
            Self::Capacity(prefixed.value)
        } else {
            Self::Duplicate(prefixed.value)
        })
    }

    fn text(reader: &mut Reader, bits: u8, flag: u8, huffman: &Huffman) -> Result<Vec<u8>, Error> {
        let prefixed = reader.prefixed(Prefix::new(bits)?)?;
        let length = usize::try_from(prefixed.value).map_err(|_| wire::Error::Range)?;
        let raw = reader.take(length)?;
        if prefixed.high & flag == 0 {
            return Ok(raw.to_vec());
        }
        Ok(huffman.decode(raw)?)
    }

    fn integer(writer: &mut Writer, bits: u8, high: u8, value: u64) -> Result<(), Error> {
        Ok(writer.prefixed(Prefix::new(bits)?, high, value)?)
    }

    fn string(
        writer: &mut Writer,
        (bits, base): (u8, u8),
        huffman: Option<&Huffman>,
        bytes: &[u8],
    ) -> Result<(), Error> {
        match huffman {
            Some(table) => {
                let coded = table.encode(bytes);
                Self::integer(writer, bits, base | (1 << bits), coded.len() as u64)?;
                writer.put(&coded);
            }
            None => {
                Self::integer(writer, bits, base, bytes.len() as u64)?;
                writer.put(bytes);
            }
        }
        Ok(())
    }
}

impl Feedback {
    pub fn decode(input: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let mut reader = Reader::new(input);
        match Self::read(input, &mut reader) {
            Ok(found) => Ok(Some((found, reader.at()))),
            Err(error) => short(error).map(|()| None),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (bits, high, value) = match self {
            Self::Acknowledge(stream) => (7, 0x80, *stream),
            Self::Cancel(stream) => (6, 0x40, *stream),
            Self::Increment(0) => return Err(Error::Zero),
            Self::Increment(count) => (6, 0x00, *count),
        };
        let mut writer = Writer::new();
        writer.prefixed(Prefix::new(bits)?, high, value)?;
        Ok(writer.finish())
    }

    fn read(input: &[u8], reader: &mut Reader) -> Result<Self, Error> {
        let lead = lead(input, reader)?;
        if lead & 0x80 != 0 {
            return Ok(Self::Acknowledge(reader.prefixed(Prefix::new(7)?)?.value));
        }
        let value = reader.prefixed(Prefix::new(6)?)?.value;
        match (lead & 0x40 != 0, value) {
            (true, stream) => Ok(Self::Cancel(stream)),
            (false, 0) => Err(Error::Zero),
            (false, count) => Ok(Self::Increment(count)),
        }
    }
}
