use crate::{Error, Hash};

pub fn sign(hash: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    match hash {
        Hash::Sha256 => {
            let mut state = radicula::Hmac::new(key);
            state.update(data);
            Ok(state.finish().to_vec())
        }
        _ => Err(Error::Unsupported),
    }
}

pub fn verify(hash: Hash, key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), Error> {
    match hash {
        Hash::Sha256 => {
            let mut state = radicula::Hmac::new(key);
            state.update(data);
            if state.verify(tag) {
                Ok(())
            } else {
                Err(Error::Auth)
            }
        }
        _ => Err(Error::Unsupported),
    }
}
