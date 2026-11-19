use crate::error::Error;
use crate::field;
use wire::{Reader, Writer};

mod typed;

pub use typed::{Identity, Place, Share, Typed};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub kind: u16,
    pub data: Vec<u8>,
}

pub fn parse(reader: &mut Reader, minimum: usize) -> Result<Vec<Extension>, Error> {
    let block = field::prefixed(reader, 2)?;
    if block.len() < minimum {
        return Err(Error::Length);
    }
    let mut inner = Reader::new(block);
    let mut found: Vec<Extension> = Vec::new();
    while inner.left() > 0 {
        let kind = field::short(&mut inner).map_err(|_| Error::Length)?;
        let data = field::prefixed(&mut inner, 2).map_err(|_| Error::Length)?;
        if found.iter().any(|seen| seen.kind == kind) {
            return Err(Error::Duplicate);
        }
        found.push(Extension {
            kind,
            data: data.to_vec(),
        });
    }
    Ok(found)
}

pub fn write(writer: &mut Writer, found: &[Extension], minimum: usize) -> Result<(), Error> {
    let mut inner = Writer::new();
    for (at, extension) in found.iter().enumerate() {
        if found[..at].iter().any(|seen| seen.kind == extension.kind) {
            return Err(Error::Duplicate);
        }
        inner.put(&extension.kind.to_be_bytes());
        field::put(&mut inner, &extension.data, 2)?;
    }
    if inner.written().len() < minimum {
        return Err(Error::Length);
    }
    field::put(writer, inner.written(), 2)
}
