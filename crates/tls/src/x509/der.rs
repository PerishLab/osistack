use super::Flaw;

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BOOLEAN: u8 = 0x01;
pub const BITS: u8 = 0x03;
pub const OCTETS: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8: u8 = 0x0c;
pub const PRINTABLE: u8 = 0x13;
pub const IA5: u8 = 0x16;
pub const UTC: u8 = 0x17;
pub const GENERAL: u8 = 0x18;

#[derive(Debug, Clone)]
pub struct Der<'a> {
    data: &'a [u8],
}

fn length(bytes: &[u8]) -> Result<(usize, usize), Flaw> {
    let first = *bytes.first().ok_or(Flaw::Length)?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return Err(Flaw::Length);
    }
    let raw = bytes.get(1..=count).ok_or(Flaw::Length)?;
    if raw[0] == 0 {
        return Err(Flaw::Minimal);
    }
    let size = raw
        .iter()
        .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
    if size < 0x80 {
        return Err(Flaw::Minimal);
    }
    Ok((size, 1 + count))
}

impl<'a> Der<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn done(&self) -> bool {
        self.data.is_empty()
    }

    pub fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub fn raw(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), Flaw> {
        let data = self.data;
        let tag = *data.first().ok_or(Flaw::Length)?;
        if tag & 0x1f == 0x1f {
            return Err(Flaw::Tag);
        }
        let (size, head) = length(&data[1..])?;
        let start = 1 + head;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= data.len())
            .ok_or(Flaw::Length)?;
        self.data = &data[end..];
        Ok((tag, &data[start..end], &data[..end]))
    }

    pub fn read(&mut self) -> Result<(u8, &'a [u8]), Flaw> {
        let (tag, content, _) = self.raw()?;
        Ok((tag, content))
    }

    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], Flaw> {
        let (found, content) = self.read()?;
        if found == tag {
            Ok(content)
        } else {
            Err(Flaw::Tag)
        }
    }

    pub fn whole(&mut self, tag: u8) -> Result<&'a [u8], Flaw> {
        let (found, _, whole) = self.raw()?;
        if found == tag {
            Ok(whole)
        } else {
            Err(Flaw::Tag)
        }
    }

    pub fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, Flaw> {
        if self.peek() == Some(tag) {
            Ok(Some(self.expect(tag)?))
        } else {
            Ok(None)
        }
    }

    pub fn finish(self) -> Result<(), Flaw> {
        if self.done() {
            Ok(())
        } else {
            Err(Flaw::Trailing)
        }
    }
}

pub fn integer(content: &[u8]) -> Result<&[u8], Flaw> {
    match content {
        [] => Err(Flaw::Value),
        [0x00, next, ..] if *next < 0x80 => Err(Flaw::Minimal),
        [0xff, next, ..] if *next >= 0x80 => Err(Flaw::Minimal),
        _ => Ok(content),
    }
}

pub fn unsigned(content: &[u8]) -> Result<u64, Flaw> {
    let bytes = integer(content)?;
    if bytes[0] >= 0x80 {
        return Err(Flaw::Value);
    }
    let digits = if bytes[0] == 0 { &bytes[1..] } else { bytes };
    if digits.len() > 8 {
        return Err(Flaw::Value);
    }
    Ok(digits
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)))
}

pub fn boolean(content: &[u8]) -> Result<bool, Flaw> {
    match content {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Flaw::Value),
    }
}
