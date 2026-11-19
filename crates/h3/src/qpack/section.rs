use crate::error::Error;
use wire::{Prefix, Reader, Writer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub required: u64,
    pub base: u64,
}

impl Section {
    pub fn read(reader: &mut Reader, capacity: usize, inserted: u64) -> Result<Self, Error> {
        let entries = (capacity / 32) as u64;
        let encoded = reader.prefixed(Prefix::new(8)?)?.value;
        let required = Self::restore(encoded, entries, inserted)?;
        let delta = reader.prefixed(Prefix::new(7)?)?;
        let base = if delta.high == 0 {
            required.checked_add(delta.value)
        } else {
            required
                .checked_sub(delta.value)
                .and_then(|rest| rest.checked_sub(1))
        };
        Ok(Self {
            required,
            base: base.ok_or(Error::Base)?,
        })
    }

    pub fn write(&self, writer: &mut Writer, capacity: usize) -> Result<(), Error> {
        let full = (capacity / 32) as u64 * 2;
        let encoded = match self.required {
            0 => 0,
            _ if full == 0 => return Err(Error::Count),
            required => required % full + 1,
        };
        writer.prefixed(Prefix::new(8)?, 0, encoded)?;
        let (sign, delta) = if self.base >= self.required {
            (0, self.base - self.required)
        } else {
            (0x80, self.required - self.base - 1)
        };
        writer.prefixed(Prefix::new(7)?, sign, delta)?;
        Ok(())
    }

    fn restore(encoded: u64, entries: u64, inserted: u64) -> Result<u64, Error> {
        if encoded == 0 {
            return Ok(0);
        }
        let full = entries * 2;
        if encoded > full {
            return Err(Error::Count);
        }
        let max = inserted.checked_add(entries).ok_or(Error::Count)?;
        let wrapped = max / full * full;
        let mut required = wrapped.checked_add(encoded - 1).ok_or(Error::Count)?;
        if required > max {
            if required <= full {
                return Err(Error::Count);
            }
            required -= full;
        }
        match required {
            0 => Err(Error::Count),
            _ => Ok(required),
        }
    }
}
