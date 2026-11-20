use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    X25519,
    Secp256r1,
}

fn fixed(bytes: &[u8]) -> Result<&[u8; 32], Error> {
    bytes.try_into().map_err(|_| Error::Length)
}

impl Group {
    pub fn secret(self) -> usize {
        32
    }

    pub fn share(self) -> usize {
        match self {
            Group::X25519 => 32,
            Group::Secp256r1 => 65,
        }
    }

    pub fn public(self, secret: &[u8]) -> Result<Vec<u8>, Error> {
        let secret = fixed(secret)?;
        match self {
            Group::X25519 => Ok(radicula::x25519::base(secret).to_vec()),
            Group::Secp256r1 => Ok(radicula::p256::ecdh::public(secret)?.to_vec()),
        }
    }

    pub fn agree(self, secret: &[u8], peer: &[u8]) -> Result<Vec<u8>, Error> {
        let secret = fixed(secret)?;
        match self {
            Group::X25519 => Ok(radicula::x25519::agree(secret, fixed(peer)?)?.to_vec()),
            Group::Secp256r1 => Ok(radicula::p256::ecdh::agree(secret, peer)?.to_vec()),
        }
    }
}
