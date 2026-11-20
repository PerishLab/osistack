use crate::error::Error;
use crypto::{Aead, Hash, Secret, hmac};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

#[derive(Clone)]
pub struct Traffic {
    hash: Hash,
    secret: Vec<u8>,
}

impl Traffic {
    pub(super) fn new(hash: Hash, secret: Vec<u8>) -> Self {
        Self { hash, secret }
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    fn prk(&self) -> Result<Secret, Error> {
        Ok(Secret::new(self.hash, &self.secret)?)
    }

    fn base(&self) -> Result<Vec<u8>, Error> {
        Ok(self.prk()?.label(b"finished", b"", self.hash.size())?)
    }

    pub fn keys(&self, aead: Aead) -> Result<Keys, Error> {
        let prk = self.prk()?;
        Ok(Keys {
            key: prk.label(b"key", b"", aead.key())?,
            iv: prk.label(b"iv", b"", Aead::NONCE)?,
        })
    }

    pub fn finished(&self, transcript: &[u8]) -> Result<Vec<u8>, Error> {
        if transcript.len() != self.hash.size() {
            return Err(Error::Length);
        }
        Ok(hmac::sign(self.hash, &self.base()?, transcript)?)
    }

    pub fn check(&self, transcript: &[u8], tag: &[u8]) -> Result<(), Error> {
        if transcript.len() != self.hash.size() {
            return Err(Error::Length);
        }
        Ok(hmac::verify(self.hash, &self.base()?, transcript, tag)?)
    }

    pub fn update(&self) -> Result<Self, Error> {
        let next = self.prk()?.label(b"traffic upd", b"", self.hash.size())?;
        Ok(Self::new(self.hash, next))
    }
}
