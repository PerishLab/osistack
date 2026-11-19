use crate::error::Error;
use crate::extension::Extension;
use crate::field::{Out, Scan};

const ALGORITHMS: u16 = 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub extensions: Vec<Extension>,
}

impl Encrypted {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let extensions = scan.extensions(0)?;
        scan.end()?;
        Ok(Self { extensions })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut out = Out::new();
        out.extensions(&self.extensions, 0)?;
        Ok(out.finish())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub context: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl Request {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let context = scan.prefixed(1)?.to_vec();
        let extensions = scan.extensions(2)?;
        scan.end()?;
        Self::check(&extensions)?;
        Ok(Self {
            context,
            extensions,
        })
    }

    fn check(extensions: &[Extension]) -> Result<(), Error> {
        if extensions.iter().any(|found| found.kind == ALGORITHMS) {
            return Ok(());
        }
        Err(Error::Missing)
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        Self::check(&self.extensions)?;
        let mut out = Out::new();
        out.prefixed(&self.context, 1)?;
        out.extensions(&self.extensions, 2)?;
        Ok(out.finish())
    }
}
