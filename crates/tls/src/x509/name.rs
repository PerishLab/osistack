use super::Flaw;
use super::der::{Der, IA5, OID, PRINTABLE, SEQUENCE, SET, UTF8};
use super::oid::Oid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub id: Oid,
    pub tag: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub der: Vec<u8>,
    pub attributes: Vec<Attribute>,
}

fn pair(content: &[u8]) -> Result<Attribute, Flaw> {
    let mut der = Der::new(content);
    let id = Oid::parse(der.expect(OID)?)?;
    let (tag, value) = der.read()?;
    der.finish()?;
    Ok(Attribute {
        id,
        tag,
        value: value.to_vec(),
    })
}

fn set(content: &[u8], out: &mut Vec<Attribute>) -> Result<(), Flaw> {
    if content.is_empty() {
        return Err(Flaw::Value);
    }
    let mut der = Der::new(content);
    while !der.done() {
        out.push(pair(der.expect(SEQUENCE)?)?);
    }
    Ok(())
}

fn printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(&byte)
}

impl Name {
    pub fn parse(whole: &[u8]) -> Result<Self, Flaw> {
        let mut top = Der::new(whole);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        let mut der = Der::new(content);
        let mut attributes = Vec::new();
        while !der.done() {
            set(der.expect(SET)?, &mut attributes)?;
        }
        Ok(Self {
            der: whole.to_vec(),
            attributes,
        })
    }

    pub fn text(&self, id: &Oid) -> Option<String> {
        let found = self
            .attributes
            .iter()
            .find(|attribute| attribute.id == *id)?;
        let value = &found.value;
        match found.tag {
            UTF8 => String::from_utf8(value.clone()).ok(),
            IA5 if value.is_ascii() => String::from_utf8(value.clone()).ok(),
            PRINTABLE if value.iter().all(|byte| printable(*byte)) => {
                String::from_utf8(value.clone()).ok()
            }
            _ => None,
        }
    }
}
