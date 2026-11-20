use super::{Master, Traffic, derive};
use crate::error::Error;
use crypto::{Hash, Secret};

#[derive(Clone)]
pub struct Schedule {
    hash: Hash,
    secret: Secret,
}

impl Schedule {
    pub fn new(hash: Hash, shared: &[u8]) -> Result<Self, Error> {
        let zeros = vec![0; hash.size()];
        let early = Secret::extract(hash, &zeros, &zeros)?;
        let salt = derive(&early, hash, b"derived", &hash.digest(b""))?;
        let secret = Secret::extract(hash, &salt, shared)?;
        Ok(Self { hash, secret })
    }

    pub fn client(&self, transcript: &[u8]) -> Result<Traffic, Error> {
        let secret = derive(&self.secret, self.hash, b"c hs traffic", transcript)?;
        Ok(Traffic::new(self.hash, secret))
    }

    pub fn server(&self, transcript: &[u8]) -> Result<Traffic, Error> {
        let secret = derive(&self.secret, self.hash, b"s hs traffic", transcript)?;
        Ok(Traffic::new(self.hash, secret))
    }

    pub fn master(&self) -> Result<Master, Error> {
        let zeros = vec![0; self.hash.size()];
        let salt = derive(&self.secret, self.hash, b"derived", &self.hash.digest(b""))?;
        let secret = Secret::extract(self.hash, &salt, &zeros)?;
        Ok(Master::new(self.hash, secret))
    }
}
