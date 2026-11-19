use crate::error::Error;
use wire::Reader;

const LIMIT: u64 = 1 << 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Number {
    pub value: u32,
    pub length: usize,
}

impl Number {
    pub fn new(full: u64, acked: Option<u64>) -> Result<Self, Error> {
        if full >= LIMIT {
            return Err(Error::Number);
        }
        let unacked = match acked {
            None => full + 1,
            Some(top) if top < full => full - top,
            Some(_) => return Err(Error::Number),
        };
        let bits = (u64::BITS - unacked.leading_zeros()) as usize;
        let length = (bits + 8) / 8;
        if length > 4 {
            return Err(Error::Number);
        }
        let mask = (1u64 << (8 * length)) - 1;
        Ok(Self {
            value: (full & mask) as u32,
            length,
        })
    }

    pub fn restore(&self, largest: Option<u64>) -> u64 {
        let expected = largest.map_or(0, |top| top.saturating_add(1));
        let window = 1u64 << (8 * self.length);
        let half = window / 2;
        let candidate = (expected & !(window - 1)) | u64::from(self.value);
        if candidate + half <= expected && candidate < LIMIT - window {
            candidate + window
        } else if candidate > expected + half && candidate >= window {
            candidate - window
        } else {
            candidate
        }
    }

    pub fn read(first: u8, bytes: &[u8]) -> Result<Self, Error> {
        let reserved = if first & 0x80 != 0 { 0x0c } else { 0x18 };
        if first & reserved != 0 {
            return Err(Error::Reserved);
        }
        let length = usize::from(first & 3) + 1;
        let raw = Reader::new(bytes).take(length)?;
        let value = raw
            .iter()
            .fold(0u32, |acc, next| (acc << 8) | u32::from(*next));
        Ok(Self { value, length })
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.value.to_be_bytes()[4 - self.length..].to_vec()
    }

    pub fn check(&self) -> Result<(), Error> {
        let fits = (1..=4).contains(&self.length);
        if !fits || u64::from(self.value) >> (8 * self.length) != 0 {
            return Err(Error::Number);
        }
        Ok(())
    }

    pub fn bits(&self) -> u8 {
        (self.length - 1) as u8
    }
}
