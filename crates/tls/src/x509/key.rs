use super::Flaw;
use super::bits::bits;
use super::der::{BITS, Der, NULL, OID, SEQUENCE, integer};
use super::oid::Oid;

const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const RSA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const RSA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const RSA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ECDSA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ECDSA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const NIL: &[u8] = &[NULL, 0x00];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithm {
    pub id: Oid,
    pub params: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Rsa256,
    Rsa384,
    Rsa512,
    Ecdsa256,
    Ecdsa384,
    Ecdsa512,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Public {
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    Ec { curve: Curve, point: Vec<u8> },
    Other(Algorithm, Vec<u8>),
}

impl Algorithm {
    pub fn parse(whole: &[u8]) -> Result<Self, Flaw> {
        let mut top = Der::new(whole);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        let mut der = Der::new(content);
        let id = Oid::parse(der.expect(OID)?)?;
        let params = if der.done() {
            None
        } else {
            let (_, _, raw) = der.raw()?;
            Some(raw.to_vec())
        };
        der.finish()?;
        Ok(Self { id, params })
    }

    pub fn scheme(&self) -> Scheme {
        let nil = self.params.as_deref() == Some(NIL);
        let none = self.params.is_none();
        match (self.id.bytes(), nil, none) {
            (RSA256, true, _) => Scheme::Rsa256,
            (RSA384, true, _) => Scheme::Rsa384,
            (RSA512, true, _) => Scheme::Rsa512,
            (ECDSA256, _, true) => Scheme::Ecdsa256,
            (ECDSA384, _, true) => Scheme::Ecdsa384,
            (ECDSA512, _, true) => Scheme::Ecdsa512,
            _ => Scheme::Other,
        }
    }
}

fn positive(content: &[u8]) -> Result<Vec<u8>, Flaw> {
    let bytes = integer(content)?;
    if bytes[0] >= 0x80 {
        return Err(Flaw::Value);
    }
    let digits = if bytes[0] == 0 { &bytes[1..] } else { bytes };
    if digits.is_empty() {
        return Err(Flaw::Value);
    }
    Ok(digits.to_vec())
}

fn rsa(data: &[u8]) -> Result<Public, Flaw> {
    let mut top = Der::new(data);
    let content = top.expect(SEQUENCE)?;
    top.finish()?;
    let mut der = Der::new(content);
    let modulus = positive(der.expect(super::der::INTEGER)?)?;
    let exponent = positive(der.expect(super::der::INTEGER)?)?;
    der.finish()?;
    Ok(Public::Rsa { modulus, exponent })
}

fn point(curve: Curve, data: &[u8]) -> Result<Public, Flaw> {
    let size = match curve {
        Curve::P256 => 65,
        Curve::P384 => 97,
        Curve::P521 => 133,
    };
    if data.len() != size || data[0] != 0x04 {
        return Err(Flaw::Value);
    }
    Ok(Public::Ec {
        curve,
        point: data.to_vec(),
    })
}

fn curved(algorithm: Algorithm, data: &[u8]) -> Result<Public, Flaw> {
    let params = algorithm.params.clone().ok_or(Flaw::Value)?;
    let mut der = Der::new(&params);
    let (tag, content) = der.read()?;
    der.finish()?;
    match (tag, content) {
        (OID, P256) => point(Curve::P256, data),
        (OID, P384) => point(Curve::P384, data),
        (OID, P521) => point(Curve::P521, data),
        (OID, _) | (SEQUENCE, _) => Ok(Public::Other(algorithm, data.to_vec())),
        _ => Err(Flaw::Value),
    }
}

impl Public {
    pub fn parse(whole: &[u8]) -> Result<Self, Flaw> {
        let mut top = Der::new(whole);
        let content = top.expect(SEQUENCE)?;
        top.finish()?;
        let mut der = Der::new(content);
        let algorithm = Algorithm::parse(der.whole(SEQUENCE)?)?;
        let (unused, data) = bits(der.expect(BITS)?)?;
        der.finish()?;
        if unused != 0 {
            return Err(Flaw::Value);
        }
        match algorithm.id.bytes() {
            RSA if algorithm.params.as_deref() == Some(NIL) => rsa(data),
            RSA => Err(Flaw::Value),
            EC => curved(algorithm, data),
            _ => Ok(Public::Other(algorithm, data.to_vec())),
        }
    }
}
