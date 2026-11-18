use crate::error::Error;
use crate::field::Field;
use crate::section::Section;
use crate::table::Table;
use wire::{Huffman, Prefix, Reader};

#[derive(Debug, Clone)]
pub struct Decoder {
    capacity: usize,
    huffman: Huffman,
}

impl Decoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            huffman: Huffman::new(),
        }
    }

    pub fn decode(&self, block: &[u8]) -> Result<Vec<Field>, Error> {
        let mut reader = Reader::new(block);
        if Section::read(&mut reader, self.capacity, 0)?.required > 0 {
            return Err(Error::Dynamic);
        }
        let mut fields = Vec::new();
        while reader.left() > 0 {
            let lead = block[reader.at()];
            fields.push(match lead {
                0xc0..=0xff => Self::indexed(&mut reader)?,
                0x50..=0x5f | 0x70..=0x7f => self.named(&mut reader)?,
                0x20..=0x3f => self.literal(&mut reader)?,
                _ => return Err(Error::Dynamic),
            });
        }
        Ok(fields)
    }

    fn indexed(reader: &mut Reader) -> Result<Field, Error> {
        let index = reader.prefixed(Prefix::new(6)?)?.value;
        Self::entry(index)
    }

    fn named(&self, reader: &mut Reader) -> Result<Field, Error> {
        let prefixed = reader.prefixed(Prefix::new(4)?)?;
        let name = Self::entry(prefixed.value)?.name;
        let value = self.string(reader)?;
        Ok(Field {
            name,
            value,
            sensitive: prefixed.high & 0x20 != 0,
        })
    }

    fn literal(&self, reader: &mut Reader) -> Result<Field, Error> {
        let prefixed = reader.prefixed(Prefix::new(3)?)?;
        let name = self.bytes(reader, prefixed.value, prefixed.high & 0x08 != 0)?;
        let value = self.string(reader)?;
        Ok(Field {
            name,
            value,
            sensitive: prefixed.high & 0x10 != 0,
        })
    }

    fn entry(index: u64) -> Result<Field, Error> {
        usize::try_from(index)
            .ok()
            .and_then(Table::get)
            .ok_or(Error::Index)
    }

    fn string(&self, reader: &mut Reader) -> Result<Vec<u8>, Error> {
        let prefixed = reader.prefixed(Prefix::new(7)?)?;
        self.bytes(reader, prefixed.value, prefixed.high & 0x80 != 0)
    }

    fn bytes(&self, reader: &mut Reader, size: u64, huffman: bool) -> Result<Vec<u8>, Error> {
        let length = usize::try_from(size).map_err(|_| wire::Error::Range)?;
        let raw = reader.take(length)?;
        if !huffman {
            return Ok(raw.to_vec());
        }
        Ok(self.huffman.decode(raw)?)
    }
}
