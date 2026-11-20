use crate::{Error, Hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Ecdsa,
    Pkcs1(Hash),
    Pss(Hash),
}

#[derive(Clone)]
pub enum Verifier {
    Ecdsa(Vec<u8>),
    Rsa(Box<radicula::rsa::Key>),
}

fn convert(hash: Hash) -> radicula::rsa::Hash {
    match hash {
        Hash::Sha256 => radicula::rsa::Hash::Sha256,
        Hash::Sha384 => radicula::rsa::Hash::Sha384,
        Hash::Sha512 => radicula::rsa::Hash::Sha512,
    }
}

impl Verifier {
    pub fn ecdsa(point: &[u8]) -> Result<Self, Error> {
        if point.len() != 65 {
            return Err(Error::Length);
        }
        Ok(Verifier::Ecdsa(point.to_vec()))
    }

    pub fn rsa(modulus: &[u8], exponent: &[u8]) -> Result<Self, Error> {
        Ok(Verifier::Rsa(Box::new(radicula::rsa::Key::new(
            modulus, exponent,
        )?)))
    }

    pub fn check(&self, scheme: Scheme, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match (self, scheme) {
            (Verifier::Ecdsa(point), Scheme::Ecdsa) => {
                Ok(radicula::p256::ecdsa::verify(point, message, signature)?)
            }
            (Verifier::Rsa(key), Scheme::Pkcs1(hash)) => {
                Ok(key.pkcs1(convert(hash), message, signature)?)
            }
            (Verifier::Rsa(key), Scheme::Pss(hash)) => {
                let digest = convert(hash);
                let salt = hash.size();
                let scheme = radicula::rsa::Pss {
                    hash: digest,
                    mgf: digest,
                    salt,
                };
                Ok(key.pss(scheme, message, signature)?)
            }
            _ => Err(Error::Unsupported),
        }
    }
}
