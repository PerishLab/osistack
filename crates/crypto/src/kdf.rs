use crate::{Error, Hash};

const PREFIX: &[u8] = b"tls13 ";

#[derive(Clone)]
enum Inner {
    Sha256(radicula::Hkdf),
    Sha384(radicula::Hkdf384),
    Sha512(radicula::Hkdf512),
}

#[derive(Clone)]
pub struct Secret {
    inner: Inner,
}

fn info(label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    let name = [PREFIX, label].concat();
    let size = u16::try_from(length).map_err(|_| Error::Length)?;
    let named = u8::try_from(name.len()).map_err(|_| Error::Length)?;
    let framed = u8::try_from(context.len()).map_err(|_| Error::Length)?;
    let mut out = size.to_be_bytes().to_vec();
    out.push(named);
    out.extend_from_slice(&name);
    out.push(framed);
    out.extend_from_slice(context);
    Ok(out)
}

impl Secret {
    pub fn extract(hash: Hash, salt: &[u8], ikm: &[u8]) -> Result<Self, Error> {
        match hash {
            Hash::Sha256 => Ok(Secret {
                inner: Inner::Sha256(radicula::Hkdf::extract(salt, ikm)),
            }),
            Hash::Sha384 => Ok(Secret {
                inner: Inner::Sha384(radicula::Hkdf384::extract(salt, ikm)),
            }),
            Hash::Sha512 => Ok(Secret {
                inner: Inner::Sha512(radicula::Hkdf512::extract(salt, ikm)),
            }),
        }
    }

    pub fn new(hash: Hash, prk: &[u8]) -> Result<Self, Error> {
        match hash {
            Hash::Sha256 => Ok(Secret {
                inner: Inner::Sha256(radicula::Hkdf::new(prk)?),
            }),
            Hash::Sha384 => Ok(Secret {
                inner: Inner::Sha384(radicula::Hkdf384::new(prk)?),
            }),
            Hash::Sha512 => Ok(Secret {
                inner: Inner::Sha512(radicula::Hkdf512::new(prk)?),
            }),
        }
    }

    pub fn expand(&self, info: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; length];
        match &self.inner {
            Inner::Sha256(inner) => inner.expand(info, &mut out)?,
            Inner::Sha384(inner) => inner.expand(info, &mut out)?,
            Inner::Sha512(inner) => inner.expand(info, &mut out)?,
        }
        Ok(out)
    }

    pub fn label(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        self.expand(&info(label, context, length)?, length)
    }
}
