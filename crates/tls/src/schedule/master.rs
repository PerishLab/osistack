use super::{Traffic, derive};
use crate::error::Error;
use crypto::{Hash, Secret};

#[derive(Clone)]
pub struct Master {
    hash: Hash,
    secret: Secret,
}

impl Master {
    pub(super) fn new(hash: Hash, secret: Secret) -> Self {
        Self { hash, secret }
    }

    pub fn client(&self, transcript: &[u8]) -> Result<Traffic, Error> {
        let secret = derive(&self.secret, self.hash, b"c ap traffic", transcript)?;
        Ok(Traffic::new(self.hash, secret))
    }

    pub fn server(&self, transcript: &[u8]) -> Result<Traffic, Error> {
        let secret = derive(&self.secret, self.hash, b"s ap traffic", transcript)?;
        Ok(Traffic::new(self.hash, secret))
    }

    pub fn exporter(&self, transcript: &[u8]) -> Result<Vec<u8>, Error> {
        derive(&self.secret, self.hash, b"exp master", transcript)
    }

    pub fn resumption(&self, transcript: &[u8]) -> Result<Vec<u8>, Error> {
        derive(&self.secret, self.hash, b"res master", transcript)
    }
}
