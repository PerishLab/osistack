use crate::error::Error;
use crate::frame::Frame;
use crate::packet::{Keys, Kind, Long, Number};
use crypto::{Aead, Hash};

pub struct Flight {
    pub kind: Kind,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
}

impl Flight {
    pub fn write(&self, keys: &Keys, number: u64, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.kind == Kind::Handshake && !self.token.is_empty() {
            return Err(Error::Token);
        }
        let written = Number::new(number, None)?;
        let long = Long {
            kind: self.kind,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            token: self.token.clone(),
            length: (written.length + payload.len() + 16) as u64,
            offset: 0,
        };
        keys.protect(number, &long.write(&written)?, payload)
    }

    pub fn crypto(
        &self,
        keys: &Keys,
        number: u64,
        data: &[u8],
        offset: u64,
    ) -> Result<Vec<u8>, Error> {
        let payload = Frame::Crypto {
            offset,
            data: data.to_vec(),
        }
        .write()?;
        self.write(keys, number, &payload)
    }
}

pub struct Applied {
    pub client: Keys,
    pub server: Keys,
}

impl Applied {
    pub fn new(hash: Hash, aead: Aead, client: &[u8], server: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            client: Keys::derive(hash, aead, client)?,
            server: Keys::derive(hash, aead, server)?,
        })
    }
}
