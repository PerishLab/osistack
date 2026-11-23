use crate::cursor::{Reader, Writer};
use crate::error::Error;

const MORE: u8 = 0x80;
const PART: u8 = 0x7f;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix(u8);

impl Prefix {
    pub fn new(bits: u8) -> Result<Self, Error> {
        if !(1..=8).contains(&bits) {
            return Err(Error::Range);
        }
        Ok(Self(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    const fn mask(self) -> u8 {
        u8::MAX >> (8 - self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packed {
    prefix: Prefix,
    high: u8,
}

impl Packed {
    pub const fn new(bits: u8, high: u8) -> Result<Self, Error> {
        if bits < 1 || bits > 8 {
            return Err(Error::Range);
        }
        let prefix = Prefix(bits);
        if high & prefix.mask() != 0 {
            return Err(Error::Range);
        }
        Ok(Self { prefix, high })
    }

    pub const fn valid(bits: u8, high: u8) -> Self {
        match Self::new(bits, high) {
            Ok(mark) => mark,
            Err(_) => panic!("packed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefixed {
    pub high: u8,
    pub value: u64,
}

fn extend(value: u64, part: u8, shift: u32) -> Result<u64, Error> {
    let part = u64::from(part);
    if shift >= u64::BITS {
        return if part == 0 {
            Ok(value)
        } else {
            Err(Error::Range)
        };
    }
    let shifted = part << shift;
    if shifted >> shift != part {
        return Err(Error::Range);
    }
    value.checked_add(shifted).ok_or(Error::Range)
}

impl Reader<'_> {
    pub fn prefixed(&mut self, prefix: Prefix) -> Result<Prefixed, Error> {
        let first = self.byte()?;
        let mask = prefix.mask();
        let high = first & !mask;
        let mut value = u64::from(first & mask);
        if first & mask < mask {
            return Ok(Prefixed { high, value });
        }
        let mut shift = 0;
        loop {
            let next = self.byte()?;
            value = extend(value, next & PART, shift)?;
            if next & MORE == 0 {
                return Ok(Prefixed { high, value });
            }
            shift += 7;
        }
    }
}

impl Writer {
    pub fn prefixed(&mut self, prefix: Prefix, high: u8, value: u64) -> Result<(), Error> {
        self.packed(Packed::new(prefix.bits(), high)?, value);
        Ok(())
    }

    pub fn packed(&mut self, packed: Packed, value: u64) {
        let mask = packed.prefix.mask();
        let high = packed.high;
        if value < u64::from(mask) {
            self.byte(high | value as u8);
            return;
        }
        self.byte(high | mask);
        let mut rest = value - u64::from(mask);
        while rest >= u64::from(MORE) {
            self.byte(rest as u8 & PART | MORE);
            rest >>= 7;
        }
        self.byte(rest as u8);
    }
}
