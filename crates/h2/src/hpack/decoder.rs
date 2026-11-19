use super::header::Header;
use super::table::Table;
use crate::error::Error;
use wire::{Huffman, Prefix, Reader};

#[derive(Debug, Clone)]
pub struct Decoder {
    table: Table,
    limit: usize,
    huffman: Huffman,
}

impl Decoder {
    pub fn new(limit: usize) -> Self {
        Self {
            table: Table::new(limit),
            limit,
            huffman: Huffman::new(),
        }
    }

    pub fn resize(&mut self, limit: usize) {
        self.limit = limit;
        self.table.resize(limit);
    }

    pub fn size(&self) -> usize {
        self.table.size()
    }

    pub fn dynamic(&self) -> Vec<Header> {
        self.table.entries()
    }

    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Header>, Error> {
        let mut reader = Reader::new(block);
        let mut headers = Vec::new();
        let mut leading = true;
        while reader.left() > 0 {
            let lead = block[reader.at()];
            if lead & 0xe0 == 0x20 {
                self.update(&mut reader, leading)?;
                continue;
            }
            leading = false;
            headers.push(match lead {
                0x80..=0xff => self.indexed(&mut reader)?,
                0x40..=0x7f => self.literal(&mut reader, 6, true)?,
                0x10..=0x1f => self.literal(&mut reader, 4, false)?.hidden(),
                _ => self.literal(&mut reader, 4, false)?,
            });
        }
        Ok(headers)
    }

    fn update(&mut self, reader: &mut Reader, leading: bool) -> Result<(), Error> {
        let size = reader.prefixed(Prefix::new(5)?)?.value;
        let limit = usize::try_from(size).map_err(|_| Error::Size)?;
        if !leading || limit > self.limit {
            return Err(Error::Size);
        }
        self.table.resize(limit);
        Ok(())
    }

    fn indexed(&mut self, reader: &mut Reader) -> Result<Header, Error> {
        let index = reader.prefixed(Prefix::new(7)?)?.value;
        let found = usize::try_from(index)
            .ok()
            .and_then(|at| self.table.get(at));
        let (name, value) = found.ok_or(Error::Index)?;
        Ok(Header::new(name, value))
    }

    fn literal(&mut self, reader: &mut Reader, bits: u8, add: bool) -> Result<Header, Error> {
        let index = reader.prefixed(Prefix::new(bits)?)?.value;
        let name = match index {
            0 => self.string(reader)?,
            _ => {
                let found = usize::try_from(index)
                    .ok()
                    .and_then(|at| self.table.get(at));
                found.ok_or(Error::Index)?.0.to_vec()
            }
        };
        let header = Header::new(&name, &self.string(reader)?);
        if add {
            self.table.add(header.clone());
        }
        Ok(header)
    }

    fn string(&self, reader: &mut Reader) -> Result<Vec<u8>, Error> {
        let prefixed = reader.prefixed(Prefix::new(7)?)?;
        let length = usize::try_from(prefixed.value).map_err(|_| Error::Size)?;
        let raw = reader.take(length)?;
        if prefixed.high & 0x80 == 0 {
            return Ok(raw.to_vec());
        }
        Ok(self.huffman.decode(raw)?)
    }
}

impl Header {
    fn hidden(self) -> Header {
        Header {
            sensitive: true,
            ..self
        }
    }
}
