use crate::error::Error;
use wire::{Reader, Varint, Writer};

pub const LIMIT: u64 = 1 << 62;
pub const STREAMS: u64 = 1 << 60;

pub struct Cursor<'a> {
    reader: Reader<'a>,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(data),
        }
    }

    pub fn left(&self) -> usize {
        self.reader.left()
    }

    pub fn at(&self) -> usize {
        self.reader.at()
    }

    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.reader.byte()?)
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        Ok(self.reader.take(count)?)
    }

    pub fn varint(&mut self) -> Result<Varint, Error> {
        Ok(self.reader.varint()?)
    }

    pub fn big(&mut self) -> Result<u64, Error> {
        Ok(self.varint()?.get())
    }

    pub fn blob(&mut self) -> Result<Vec<u8>, Error> {
        let size = self.big()?;
        let size = usize::try_from(size).map_err(|_| wire::Error::Truncated)?;
        Ok(self.take(size)?.to_vec())
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut found = [0u8; N];
        found.copy_from_slice(self.take(N)?);
        Ok(found)
    }

    pub fn cid(&mut self) -> Result<Vec<u8>, Error> {
        let size = usize::from(self.byte()?);
        if !(1..=20).contains(&size) {
            return Err(Error::Length);
        }
        Ok(self.take(size)?.to_vec())
    }
}

pub fn within(value: u64, maximum: u64) -> Result<u64, Error> {
    if value > maximum {
        return Err(Error::Value);
    }
    Ok(value)
}

pub fn put(writer: &mut Writer, value: u64) -> Result<(), Error> {
    writer.varint(Varint::new(value)?);
    Ok(())
}

pub fn pack(writer: &mut Writer, bytes: &[u8]) -> Result<(), Error> {
    put(writer, bytes.len() as u64)?;
    writer.put(bytes);
    Ok(())
}

pub fn ident(writer: &mut Writer, bytes: &[u8]) -> Result<(), Error> {
    if !(1..=20).contains(&bytes.len()) {
        return Err(Error::Length);
    }
    writer.byte(bytes.len() as u8);
    writer.put(bytes);
    Ok(())
}
