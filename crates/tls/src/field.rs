use crate::error::Error;
use crate::extension::{self, Extension};
use wire::{Reader, Writer};

pub fn short(reader: &mut Reader) -> Result<u16, Error> {
    let high = reader.byte()?;
    let low = reader.byte()?;
    Ok(u16::from_be_bytes([high, low]))
}

pub fn size(reader: &mut Reader, width: usize) -> Result<usize, Error> {
    let raw = reader.take(width)?;
    let value = raw
        .iter()
        .fold(0usize, |acc, next| (acc << 8) | usize::from(*next));
    Ok(value)
}

pub fn prefixed<'a>(reader: &mut Reader<'a>, width: usize) -> Result<&'a [u8], Error> {
    let length = size(reader, width)?;
    Ok(reader.take(length)?)
}

pub fn put(writer: &mut Writer, bytes: &[u8], width: usize) -> Result<(), Error> {
    if bytes.len() >> (8 * width) != 0 {
        return Err(Error::Length);
    }
    let length = (bytes.len() as u64).to_be_bytes();
    writer.put(&length[8 - width..]);
    writer.put(bytes);
    Ok(())
}

pub struct Scan<'a> {
    reader: Reader<'a>,
}

impl<'a> Scan<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            reader: Reader::new(data),
        }
    }

    pub fn left(&self) -> usize {
        self.reader.left()
    }

    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.reader.byte()?)
    }

    pub fn short(&mut self) -> Result<u16, Error> {
        short(&mut self.reader)
    }

    pub fn long(&mut self) -> Result<u32, Error> {
        let raw = self.reader.take(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    pub fn prefixed(&mut self, width: usize) -> Result<&'a [u8], Error> {
        prefixed(&mut self.reader, width)
    }

    pub fn extensions(&mut self, minimum: usize) -> Result<Vec<Extension>, Error> {
        extension::parse(&mut self.reader, minimum)
    }

    pub fn end(&self) -> Result<(), Error> {
        if self.reader.left() > 0 {
            return Err(Error::Trailing);
        }
        Ok(())
    }
}

pub struct Out {
    writer: Writer,
}

impl Out {
    pub fn new() -> Self {
        Self {
            writer: Writer::new(),
        }
    }

    pub fn short(&mut self, value: u16) {
        self.writer.put(&value.to_be_bytes());
    }

    pub fn long(&mut self, value: u32) {
        self.writer.put(&value.to_be_bytes());
    }

    pub fn prefixed(&mut self, bytes: &[u8], width: usize) -> Result<(), Error> {
        put(&mut self.writer, bytes, width)
    }

    pub fn extensions(&mut self, found: &[Extension], minimum: usize) -> Result<(), Error> {
        extension::write(&mut self.writer, found, minimum)
    }

    pub fn finish(self) -> Vec<u8> {
        self.writer.finish()
    }
}
