use crate::error::Error;
use crate::token;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name(String);

impl Name {
    pub fn new(text: &str) -> Result<Self, Error> {
        token::check(text)?;
        Ok(Self(text.to_ascii_lowercase()))
    }

    pub fn text(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Value(Vec<u8>);

fn allowed(byte: u8) -> bool {
    byte == b'\t' || (0x20..=0x7e).contains(&byte) || byte >= 0x80
}

fn padding(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

impl Value {
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if !bytes.iter().copied().all(allowed) {
            return Err(Error::Character);
        }
        let first = bytes.first().copied().is_some_and(padding);
        let last = bytes.last().copied().is_some_and(padding);
        if first || last {
            return Err(Error::Padding);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
