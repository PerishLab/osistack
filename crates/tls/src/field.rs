use crate::error::Error;
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
