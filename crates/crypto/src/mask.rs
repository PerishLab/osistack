use crate::{Aead, Error};

pub enum Mask {
    Aes(Box<radicula::Aes>),
    Chacha([u8; 32]),
}

impl Mask {
    pub fn new(aead: Aead, key: &[u8]) -> Result<Self, Error> {
        if key.len() != aead.key() {
            return Err(Error::Length);
        }
        match aead {
            Aead::Chacha => {
                let fixed: &[u8; 32] = key.try_into().map_err(|_| Error::Length)?;
                Ok(Mask::Chacha(*fixed))
            }
            _ => Ok(Mask::Aes(Box::new(radicula::Aes::new(key)?))),
        }
    }

    pub fn mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        let block = match self {
            Mask::Aes(inner) => {
                let mut block = *sample;
                inner.encrypt(&mut block);
                block
            }
            Mask::Chacha(key) => chacha(key, sample),
        };
        [block[0], block[1], block[2], block[3], block[4]]
    }
}

fn chacha(key: &[u8; 32], sample: &[u8; 16]) -> [u8; 16] {
    let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sample[4..]);
    let stream = radicula::Chacha20::block(key, &nonce, counter);
    let mut out = [0u8; 16];
    out.copy_from_slice(&stream[..16]);
    out
}

impl Drop for Mask {
    fn drop(&mut self) {
        if let Mask::Chacha(key) = self {
            radicula::ct::wipe(key);
        }
    }
}
