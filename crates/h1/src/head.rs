use crate::error::Error;
use crate::line::{blank, clean, find, trim};
use http::{Name, Status, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Name,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub version: Version,
    pub status: Status,
    pub reason: String,
    pub fields: Vec<Field>,
}

impl Head {
    pub fn parse(input: &[u8], limit: usize) -> Result<Option<(Head, usize)>, Error> {
        let end = find(input, b"\r\n\r\n").map(|at| at + 4);
        clean(&input[..end.unwrap_or(input.len())])?;
        let Some(end) = end else {
            return if input.len() > limit {
                Err(Error::Size)
            } else {
                Ok(None)
            };
        };
        if end > limit {
            return Err(Error::Size);
        }
        let text = &input[..end - 4];
        let split = find(text, b"\r\n").unwrap_or(text.len());
        let (version, status, reason) = status(&text[..split])?;
        let mut fields = Vec::new();
        if split < text.len() {
            for line in text[split + 2..].split(|byte| *byte == b'\n') {
                fields.push(field(line.strip_suffix(b"\r").unwrap_or(line))?);
            }
        }
        Ok(Some((
            Head {
                version,
                status,
                reason,
                fields,
            },
            end,
        )))
    }

    pub fn values(&self, name: &str) -> Vec<&[u8]> {
        named(&self.fields, name)
    }
}

fn status(line: &[u8]) -> Result<(Version, Status, String), Error> {
    let version = match line.get(..8) {
        Some(b"HTTP/1.1") => Version::Http11,
        Some(b"HTTP/1.0") => Version::Http10,
        Some(other) if other.starts_with(b"HTTP/") => return Err(Error::Version),
        _ => return Err(Error::Line),
    };
    let rest = &line[8..];
    let digits = rest
        .strip_prefix(b" ")
        .and_then(|tail| tail.get(..3))
        .ok_or(Error::Line)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::Status);
    }
    let code = digits
        .iter()
        .fold(0u16, |sum, digit| sum * 10 + (digit - b'0') as u16);
    let status = Status::new(code).map_err(|_| Error::Status)?;
    let reason = match &rest[4..] {
        [] => &[][..],
        [b' ', tail @ ..] => tail,
        _ => return Err(Error::Line),
    };
    let plain = |byte: &u8| blank(*byte) || (0x21..=0x7e).contains(byte) || *byte >= 0x80;
    if !reason.iter().all(plain) {
        return Err(Error::Line);
    }
    Ok((
        version,
        status,
        String::from_utf8_lossy(reason).into_owned(),
    ))
}

fn field(line: &[u8]) -> Result<Field, Error> {
    if line.first().is_some_and(|byte| blank(*byte)) {
        return Err(Error::Fold);
    }
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(Error::Field)?;
    let name = &line[..colon];
    if name.last().is_some_and(|byte| blank(*byte)) {
        return Err(Error::Space);
    }
    let text = std::str::from_utf8(name).map_err(|_| Error::Field)?;
    let name = Name::new(text).map_err(|_| Error::Field)?;
    let value = Value::new(trim(&line[colon + 1..])).map_err(|_| Error::Field)?;
    Ok(Field { name, value })
}

pub fn named<'a>(fields: &'a [Field], name: &str) -> Vec<&'a [u8]> {
    let wanted = name.to_ascii_lowercase();
    let found = fields.iter().filter(|field| field.name.text() == wanted);
    found.map(|field| field.value.bytes()).collect()
}
