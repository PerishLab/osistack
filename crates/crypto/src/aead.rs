use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    Aes128,
    Aes256,
    Chacha,
}

impl Aead {
    pub const NONCE: usize = 12;
    pub const TAG: usize = 16;

    pub fn key(self) -> usize {
        match self {
            Aead::Aes128 => 16,
            Aead::Aes256 | Aead::Chacha => 32,
        }
    }

    pub fn cipher(self, key: &[u8]) -> Result<Cipher, Error> {
        if key.len() != self.key() {
            return Err(Error::Length);
        }
        match self {
            Aead::Chacha => {
                let fixed: &[u8; 32] = key.try_into().map_err(|_| Error::Length)?;
                Ok(Cipher::Chacha(radicula::Chacha20poly1305::new(fixed)))
            }
            _ => Ok(Cipher::Gcm(Box::new(radicula::Aesgcm::new(key)?))),
        }
    }
}

pub enum Cipher {
    Gcm(Box<radicula::Aesgcm>),
    Chacha(radicula::Chacha20poly1305),
}

impl Cipher {
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> Result<[u8; 16], Error> {
        let tag = match self {
            Cipher::Gcm(inner) => inner.seal(nonce, aad, data)?,
            Cipher::Chacha(inner) => inner.seal(nonce, aad, data)?,
        };
        Ok(tag)
    }

    pub fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        if tag.len() != Aead::TAG {
            return Err(Error::Length);
        }
        match self {
            Cipher::Gcm(inner) => inner.open(nonce, aad, data, tag)?,
            Cipher::Chacha(inner) => inner.open(nonce, aad, data, tag)?,
        }
        Ok(())
    }
}
