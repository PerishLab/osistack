use crate::cursor::{Reader, Writer};
use crate::error::Error;

const LIMIT: u64 = 1 << 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Varint(u64);

impl Varint {
    pub fn new(value: u64) -> Result<Self, Error> {
        if value >= LIMIT {
            return Err(Error::Range);
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn size(self) -> usize {
        match self.0 {
            0..=63 => 1,
            64..=16383 => 2,
            16384..=1073741823 => 4,
            _ => 8,
        }
    }
}

impl Reader<'_> {
    pub fn varint(&mut self) -> Result<Varint, Error> {
        let first = self.byte()?;
        let length = 1usize << (first >> 6);
        let rest = self.take(length - 1)?;
        let head = u64::from(first & 0x3f);
        let value = rest
            .iter()
            .fold(head, |acc, next| (acc << 8) | u64::from(*next));
        Ok(Varint(value))
    }
}

impl Writer {
    pub fn varint(&mut self, value: Varint) {
        let length = value.size();
        let prefix = u64::from(length.trailing_zeros()) << (8 * length - 2);
        let encoded = (value.0 | prefix).to_be_bytes();
        self.put(&encoded[8 - length..]);
    }
}
