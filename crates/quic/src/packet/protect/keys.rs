use crate::error::Error;
use crate::packet::ident::LIMIT;
use crypto::{Aead, Hash, Secret};

const SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

#[derive(Clone)]
pub struct Keys {
    pub(super) aead: Aead,
    pub(super) key: Vec<u8>,
    pub(super) iv: Vec<u8>,
    pub(super) hp: Vec<u8>,
    hash: Hash,
    secret: Vec<u8>,
}

pub struct Initial {
    pub client: Keys,
    pub server: Keys,
}

impl Initial {
    pub fn new(dcid: &[u8]) -> Result<Self, Error> {
        if dcid.len() > LIMIT {
            return Err(Error::Length);
        }
        let hash = Hash::Sha256;
        let root = Secret::extract(hash, &SALT, dcid)?;
        let client = root.label(b"client in", b"", hash.size())?;
        let server = root.label(b"server in", b"", hash.size())?;
        Ok(Self {
            client: Keys::derive(hash, Aead::Aes128, &client)?,
            server: Keys::derive(hash, Aead::Aes128, &server)?,
        })
    }
}

impl Keys {
    pub fn derive(hash: Hash, aead: Aead, secret: &[u8]) -> Result<Self, Error> {
        Self::build(hash, aead, secret, None)
    }

    pub fn update(&self) -> Result<Self, Error> {
        let prk = Secret::new(self.hash, &self.secret)?;
        let next = prk.label(b"quic ku", b"", self.hash.size())?;
        Self::build(self.hash, self.aead, &next, Some(self.hp.clone()))
    }

    fn build(hash: Hash, aead: Aead, secret: &[u8], hp: Option<Vec<u8>>) -> Result<Self, Error> {
        let prk = Secret::new(hash, secret)?;
        let hp = match hp {
            Some(kept) => kept,
            None => prk.label(b"quic hp", b"", aead.key())?,
        };
        Ok(Self {
            aead,
            key: prk.label(b"quic key", b"", aead.key())?,
            iv: prk.label(b"quic iv", b"", Aead::NONCE)?,
            hp,
            hash,
            secret: secret.to_vec(),
        })
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    pub fn hp(&self) -> &[u8] {
        &self.hp
    }
}
