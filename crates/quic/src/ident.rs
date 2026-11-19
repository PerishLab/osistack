use crate::error::Error;
use wire::{Reader, Writer};

pub const LIMIT: usize = 20;

pub fn word(reader: &mut Reader) -> Result<u32, Error> {
    let raw = reader.take(4)?;
    Ok(raw
        .iter()
        .fold(0u32, |acc, next| (acc << 8) | u32::from(*next)))
}

pub fn take(reader: &mut Reader, limit: usize) -> Result<Vec<u8>, Error> {
    let length = usize::from(reader.byte()?);
    if length > limit {
        return Err(Error::Length);
    }
    Ok(reader.take(length)?.to_vec())
}

pub fn put(writer: &mut Writer, ident: &[u8], limit: usize) -> Result<(), Error> {
    if ident.len() > limit {
        return Err(Error::Length);
    }
    writer.byte(ident.len() as u8);
    writer.put(ident);
    Ok(())
}
