use super::Flaw;
use super::bits::bits;
use super::der::{BITS, Der, INTEGER, SEQUENCE, integer, unsigned};
use super::ext::{self, Basic, Extension, General};
use super::key::{Algorithm, Public};
use super::name::Name;
use super::oid::Oid;
use super::time::Time;

const ALT: &[u8] = &[0x55, 0x1d, 0x11];
const BASIC: &[u8] = &[0x55, 0x1d, 0x13];
const USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const PURPOSE: &[u8] = &[0x55, 0x1d, 0x25];

#[derive(Debug, Clone)]
pub struct Certificate {
    pub tbs: Vec<u8>,
    pub version: u8,
    pub serial: Vec<u8>,
    pub algorithm: Algorithm,
    pub issuer: Name,
    pub from: Time,
    pub until: Time,
    pub subject: Name,
    pub spki: Vec<u8>,
    pub key: Public,
    pub extensions: Vec<Extension>,
    pub alt: Option<Vec<General>>,
    pub basic: Option<Basic>,
    pub usage: Option<u16>,
    pub purposes: Option<Vec<Oid>>,
    pub outer: Algorithm,
    pub signature: Vec<u8>,
}

struct Reader<'a> {
    der: Der<'a>,
}

impl<'a> Reader<'a> {
    fn new(content: &'a [u8]) -> Self {
        Self {
            der: Der::new(content),
        }
    }

    fn version(&mut self) -> Result<u8, Flaw> {
        let Some(inner) = self.der.optional(0xa0)? else {
            return Ok(1);
        };
        let mut wrapped = Der::new(inner);
        let number = unsigned(wrapped.expect(INTEGER)?)?;
        wrapped.finish()?;
        match number {
            1 => Ok(2),
            2 => Ok(3),
            _ => Err(Flaw::Version),
        }
    }

    fn moment(&mut self) -> Result<Time, Flaw> {
        let (tag, content) = self.der.read()?;
        Time::parse(tag, content)
    }

    fn unique(&mut self, version: u8) -> Result<(), Flaw> {
        for tag in [0x81, 0x82] {
            let Some(content) = self.der.optional(tag)? else {
                continue;
            };
            bits(content)?;
            if version < 2 {
                return Err(Flaw::Version);
            }
        }
        Ok(())
    }

    fn extensions(&mut self, version: u8) -> Result<Vec<Extension>, Flaw> {
        let Some(inner) = self.der.optional(0xa3)? else {
            return Ok(Vec::new());
        };
        if version < 3 {
            return Err(Flaw::Version);
        }
        let mut wrapped = Der::new(inner);
        let content = wrapped.expect(SEQUENCE)?;
        wrapped.finish()?;
        ext::list(content)
    }
}

fn validity(content: &[u8]) -> Result<(Time, Time), Flaw> {
    let mut reader = Reader::new(content);
    let from = reader.moment()?;
    let until = reader.moment()?;
    reader.der.finish()?;
    Ok((from, until))
}

fn body(
    tbs: &[u8],
    content: &[u8],
    outer: Algorithm,
    signature: Vec<u8>,
) -> Result<Certificate, Flaw> {
    let mut reader = Reader::new(content);
    let version = reader.version()?;
    let serial = integer(reader.der.expect(INTEGER)?)?.to_vec();
    let algorithm = Algorithm::parse(reader.der.whole(SEQUENCE)?)?;
    let issuer = Name::parse(reader.der.whole(SEQUENCE)?)?;
    let (from, until) = validity(reader.der.expect(SEQUENCE)?)?;
    let subject = Name::parse(reader.der.whole(SEQUENCE)?)?;
    let spki = reader.der.whole(SEQUENCE)?;
    let key = Public::parse(spki)?;
    reader.unique(version)?;
    let extensions = reader.extensions(version)?;
    reader.der.finish()?;
    Ok(Certificate {
        tbs: tbs.to_vec(),
        version,
        serial,
        algorithm,
        issuer,
        from,
        until,
        subject,
        spki: spki.to_vec(),
        key,
        extensions,
        alt: None,
        basic: None,
        usage: None,
        purposes: None,
        outer,
        signature,
    })
}

impl Certificate {
    pub fn parse(der: &[u8]) -> Result<Self, Flaw> {
        let mut top = Der::new(der);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        let mut parts = Der::new(content);
        let (tag, inner, tbs) = parts.raw()?;
        if tag != SEQUENCE {
            return Err(Flaw::Tag);
        }
        let outer = Algorithm::parse(parts.whole(SEQUENCE)?)?;
        let (unused, data) = bits(parts.expect(BITS)?)?;
        parts.finish()?;
        if unused != 0 {
            return Err(Flaw::Value);
        }
        let mut cert = body(tbs, inner, outer, data.to_vec())?;
        if cert.algorithm != cert.outer {
            return Err(Flaw::Mismatch);
        }
        cert.typed()?;
        Ok(cert)
    }

    fn typed(&mut self) -> Result<(), Flaw> {
        for extension in &self.extensions {
            match extension.id.bytes() {
                ALT => self.alt = Some(extension.names()?),
                BASIC => self.basic = Some(extension.basic()?),
                USAGE => self.usage = Some(extension.usage()?),
                PURPOSE => self.purposes = Some(extension.purposes()?),
                _ => {}
            }
        }
        Ok(())
    }
}
