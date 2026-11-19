use crate::error::Error;
use crate::qpack::field::Field;
use crate::qpack::section::Section;
use crate::qpack::tables::{Dynamic, Table};
use wire::{Huffman, Prefix, Reader};

pub struct Lines<'a> {
    huffman: &'a Huffman,
    table: &'a Dynamic,
    section: Section,
}

impl<'a> Lines<'a> {
    pub fn new(huffman: &'a Huffman, table: &'a Dynamic, section: Section) -> Self {
        Self {
            huffman,
            table,
            section,
        }
    }

    pub fn all(&self, block: &[u8]) -> Result<Vec<Field>, Error> {
        let mut reader = Reader::new(block);
        let mut fields = Vec::new();
        while reader.left() > 0 {
            let lead = block[reader.at()];
            fields.push(self.line(&mut reader, lead)?);
        }
        Ok(fields)
    }

    fn line(&self, reader: &mut Reader, lead: u8) -> Result<Field, Error> {
        match lead {
            0xc0..=0xff => Self::indexed(reader),
            0x80..=0xbf => self.relative(reader),
            0x10..=0x1f => self.after(reader),
            0x50..=0x5f | 0x70..=0x7f => self.fixed(reader),
            0x40..=0x4f | 0x60..=0x6f => self.behind(reader),
            0x00..=0x0f => self.ahead(reader),
            0x20..=0x3f => self.literal(reader),
        }
    }

    fn indexed(reader: &mut Reader) -> Result<Field, Error> {
        let index = reader.prefixed(Prefix::new(6)?)?.value;
        Self::entry(index)
    }

    fn relative(&self, reader: &mut Reader) -> Result<Field, Error> {
        let index = reader.prefixed(Prefix::new(6)?)?.value;
        self.recall(
            self.section
                .base
                .checked_sub(1)
                .and_then(|last| last.checked_sub(index)),
        )
    }

    fn after(&self, reader: &mut Reader) -> Result<Field, Error> {
        let index = reader.prefixed(Prefix::new(4)?)?.value;
        self.recall(self.section.base.checked_add(index))
    }

    fn fixed(&self, reader: &mut Reader) -> Result<Field, Error> {
        let prefixed = reader.prefixed(Prefix::new(4)?)?;
        let name = Self::entry(prefixed.value)?.name;
        self.finish(reader, name, prefixed.high & 0x20 != 0)
    }

    fn behind(&self, reader: &mut Reader) -> Result<Field, Error> {
        let prefixed = reader.prefixed(Prefix::new(4)?)?;
        let last = self.section.base.checked_sub(1);
        let name = self
            .recall(last.and_then(|last| last.checked_sub(prefixed.value)))?
            .name;
        self.finish(reader, name, prefixed.high & 0x20 != 0)
    }

    fn ahead(&self, reader: &mut Reader) -> Result<Field, Error> {
        let prefixed = reader.prefixed(Prefix::new(3)?)?;
        let name = self
            .recall(self.section.base.checked_add(prefixed.value))?
            .name;
        self.finish(reader, name, prefixed.high & 0x08 != 0)
    }

    fn literal(&self, reader: &mut Reader) -> Result<Field, Error> {
        let prefixed = reader.prefixed(Prefix::new(3)?)?;
        let name = self.bytes(reader, prefixed.value, prefixed.high & 0x08 != 0)?;
        self.finish(reader, name, prefixed.high & 0x10 != 0)
    }

    fn finish(&self, reader: &mut Reader, name: Vec<u8>, sensitive: bool) -> Result<Field, Error> {
        let value = self.string(reader)?;
        Ok(Field {
            name,
            value,
            sensitive,
        })
    }

    fn recall(&self, absolute: Option<u64>) -> Result<Field, Error> {
        if self.section.required == 0 {
            return Err(Error::Dynamic);
        }
        let absolute = absolute.ok_or(Error::Reference)?;
        if absolute >= self.section.required {
            return Err(Error::Reference);
        }
        self.table.get(absolute).cloned().ok_or(Error::Index)
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
