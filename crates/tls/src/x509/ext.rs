use super::Flaw;
use super::bits::bits;
use super::der::{BITS, BOOLEAN, Der, INTEGER, OCTETS, OID, SEQUENCE, boolean, unsigned};
use super::oid::Oid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub id: Oid,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum General {
    Dns(String),
    Ip(Vec<u8>),
    Email(String),
    Uri(String),
    Other(u8, Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Basic {
    pub ca: bool,
    pub depth: Option<u64>,
}

fn single(content: &[u8]) -> Result<Extension, Flaw> {
    let mut der = Der::new(content);
    let id = Oid::parse(der.expect(OID)?)?;
    let critical = match der.optional(BOOLEAN)? {
        Some(raw) if boolean(raw)? => true,
        Some(_) => return Err(Flaw::Value),
        None => false,
    };
    let value = der.expect(OCTETS)?.to_vec();
    der.finish()?;
    Ok(Extension {
        id,
        critical,
        value,
    })
}

pub fn list(content: &[u8]) -> Result<Vec<Extension>, Flaw> {
    if content.is_empty() {
        return Err(Flaw::Value);
    }
    let mut der = Der::new(content);
    let mut out: Vec<Extension> = Vec::new();
    while !der.done() {
        let next = single(der.expect(SEQUENCE)?)?;
        if out.iter().any(|seen| seen.id == next.id) {
            return Err(Flaw::Duplicate);
        }
        out.push(next);
    }
    Ok(out)
}

fn text(content: &[u8]) -> Result<String, Flaw> {
    if !content.is_ascii() {
        return Err(Flaw::Value);
    }
    String::from_utf8(content.to_vec()).map_err(|_| Flaw::Value)
}

fn general(tag: u8, content: &[u8]) -> Result<General, Flaw> {
    match (tag, content.len()) {
        (0x82, _) => Ok(General::Dns(text(content)?)),
        (0x81, _) => Ok(General::Email(text(content)?)),
        (0x86, _) => Ok(General::Uri(text(content)?)),
        (0x87, 4) | (0x87, 16) => Ok(General::Ip(content.to_vec())),
        (0x87, _) => Err(Flaw::Value),
        _ => Ok(General::Other(tag, content.to_vec())),
    }
}

impl Extension {
    pub fn names(&self) -> Result<Vec<General>, Flaw> {
        let mut top = Der::new(&self.value);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        if content.is_empty() {
            return Err(Flaw::Value);
        }
        let mut der = Der::new(content);
        let mut out = Vec::new();
        while !der.done() {
            let (tag, body) = der.read()?;
            out.push(general(tag, body)?);
        }
        Ok(out)
    }

    pub fn basic(&self) -> Result<Basic, Flaw> {
        let mut top = Der::new(&self.value);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        let mut der = Der::new(content);
        let ca = match der.optional(BOOLEAN)? {
            Some(raw) if boolean(raw)? => true,
            Some(_) => return Err(Flaw::Value),
            None => false,
        };
        let depth = match der.optional(INTEGER)? {
            Some(raw) => Some(unsigned(raw)?),
            None => None,
        };
        der.finish()?;
        Ok(Basic { ca, depth })
    }

    pub fn usage(&self) -> Result<u16, Flaw> {
        let mut der = Der::new(&self.value);
        let content = der.expect(BITS)?;
        der.finish()?;
        let (unused, data) = bits(content)?;
        if data.is_empty() || data.len() > 2 || data.len() * 8 - usize::from(unused) > 9 {
            return Err(Flaw::Value);
        }
        let mut out = 0u16;
        for index in 0..data.len() * 8 {
            if data[index / 8] >> (7 - index % 8) & 1 == 1 {
                out |= 1 << index;
            }
        }
        if out == 0 {
            return Err(Flaw::Value);
        }
        Ok(out)
    }

    pub fn purposes(&self) -> Result<Vec<Oid>, Flaw> {
        let mut top = Der::new(&self.value);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        if content.is_empty() {
            return Err(Flaw::Value);
        }
        let mut der = Der::new(content);
        let mut out = Vec::new();
        while !der.done() {
            out.push(Oid::parse(der.expect(OID)?)?);
        }
        Ok(out)
    }
}
