use crate::error::Error;
use crate::field::{Cursor, LIMIT, put};
use wire::Writer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub id: u64,
    pub offset: u64,
    pub data: Vec<u8>,
    pub fin: bool,
    pub sized: bool,
}

impl Stream {
    pub fn read(reader: &mut Cursor, code: u8) -> Result<Self, Error> {
        let id = reader.big()?;
        let offset = if code & 0x04 != 0 { reader.big()? } else { 0 };
        let sized = code & 0x02 != 0;
        let data = if sized {
            let size = reader.big()?;
            let size = usize::try_from(size).map_err(|_| wire::Error::Truncated)?;
            reader.take(size)?.to_vec()
        } else {
            let rest = reader.left();
            reader.take(rest)?.to_vec()
        };
        let stream = Self {
            id,
            offset,
            data,
            fin: code & 0x01 != 0,
            sized,
        };
        stream.check()?;
        Ok(stream)
    }

    pub fn check(&self) -> Result<(), Error> {
        Self::span(self.offset, self.data.len())
    }

    pub fn span(offset: u64, size: usize) -> Result<(), Error> {
        let end = offset.checked_add(size as u64);
        if end.is_none_or(|value| value >= LIMIT) {
            return Err(Error::Value);
        }
        Ok(())
    }

    pub fn write(&self, writer: &mut Writer) -> Result<(), Error> {
        self.check()?;
        let offset = u8::from(self.offset > 0) << 2;
        let sized = u8::from(self.sized) << 1;
        writer.byte(0x08 | offset | sized | u8::from(self.fin));
        put(writer, self.id)?;
        if self.offset > 0 {
            put(writer, self.offset)?;
        }
        if self.sized {
            put(writer, self.data.len() as u64)?;
        }
        writer.put(&self.data);
        Ok(())
    }
}
