use crate::error::Error;
use crate::field::{Cursor, put};
use wire::Writer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecn {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub largest: u64,
    pub delay: u64,
    pub first: u64,
    pub ranges: Vec<(u64, u64)>,
    pub ecn: Option<Ecn>,
}

impl Ack {
    pub fn read(reader: &mut Cursor, counted: bool) -> Result<Self, Error> {
        let largest = reader.big()?;
        let delay = reader.big()?;
        let count = reader.big()?;
        let first = reader.big()?;
        let mut ranges = Vec::new();
        for _ in 0..count {
            let gap = reader.big()?;
            let length = reader.big()?;
            ranges.push((gap, length));
        }
        let ecn = if counted {
            Some(Ecn {
                ect0: reader.big()?,
                ect1: reader.big()?,
                ce: reader.big()?,
            })
        } else {
            None
        };
        let ack = Self {
            largest,
            delay,
            first,
            ranges,
            ecn,
        };
        ack.check()?;
        Ok(ack)
    }

    pub fn check(&self) -> Result<(), Error> {
        let mut smallest = self.largest.checked_sub(self.first).ok_or(Error::Value)?;
        for (gap, length) in &self.ranges {
            let top = smallest
                .checked_sub(*gap)
                .and_then(|value| value.checked_sub(2))
                .ok_or(Error::Value)?;
            smallest = top.checked_sub(*length).ok_or(Error::Value)?;
        }
        Ok(())
    }

    pub fn write(&self, writer: &mut Writer) -> Result<(), Error> {
        self.check()?;
        writer.byte(if self.ecn.is_some() { 0x03 } else { 0x02 });
        put(writer, self.largest)?;
        put(writer, self.delay)?;
        put(writer, self.ranges.len() as u64)?;
        put(writer, self.first)?;
        for (gap, length) in &self.ranges {
            put(writer, *gap)?;
            put(writer, *length)?;
        }
        if let Some(ecn) = &self.ecn {
            put(writer, ecn.ect0)?;
            put(writer, ecn.ect1)?;
            put(writer, ecn.ce)?;
        }
        Ok(())
    }
}
