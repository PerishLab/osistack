use crate::{Error, Hash};

pub fn sign(hash: Hash, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    match hash {
        Hash::Sha256 => {
            let mut state = radicula::Hmac::new(key);
            state.update(data);
            Ok(state.finish().to_vec())
        }
        Hash::Sha384 => {
            let mut state = radicula::Hmac384::new(key);
            state.update(data);
            Ok(state.finish().to_vec())
        }
        Hash::Sha512 => {
            let mut state = radicula::Hmac512::new(key);
            state.update(data);
            Ok(state.finish().to_vec())
        }
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
        Hash::Sha384 => {
            let mut state = radicula::Hmac384::new(key);
            state.update(data);
            if state.verify(tag) {
                Ok(())
            } else {
                Err(Error::Auth)
            }
        }
        Hash::Sha512 => {
            let mut state = radicula::Hmac512::new(key);
            state.update(data);
            if state.verify(tag) {
                Ok(())
            } else {
                Err(Error::Auth)
            }
        }
    }
}
