use crate::error::Error;
use crate::field::{Out, Scan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verify {
    pub algorithm: u16,
    pub signature: Vec<u8>,
}

impl Verify {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let algorithm = scan.short()?;
        let signature = scan.prefixed(2)?.to_vec();
        scan.end()?;
        Ok(Self {
            algorithm,
            signature,
        })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut out = Out::new();
        out.short(self.algorithm);
        out.prefixed(&self.signature, 2)?;
        Ok(out.finish())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub data: Vec<u8>,
}

impl Finished {
    pub fn parse(body: &[u8], size: usize) -> Result<Self, Error> {
        if body.len() != size {
            return Err(Error::Length);
        }
        Ok(Self {
            data: body.to_vec(),
        })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        Ok(self.data.clone())
    }
}
