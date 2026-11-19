use crate::error::Error;
use crate::extension::Extension;
use crate::field::{Out, Scan};

const WEEK: u32 = 604_800;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub lifetime: u32,
    pub add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl Ticket {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let lifetime = scan.long()?;
        let add = scan.long()?;
        let nonce = scan.prefixed(1)?.to_vec();
        let ticket = scan.prefixed(2)?.to_vec();
        let extensions = scan.extensions(0)?;
        scan.end()?;
        let found = Self {
            lifetime,
            add,
            nonce,
            ticket,
            extensions,
        };
        found.check()?;
        Ok(found)
    }

    fn check(&self) -> Result<(), Error> {
        if self.lifetime > WEEK {
            return Err(Error::Value);
        }
        if self.ticket.is_empty() {
            return Err(Error::Length);
        }
        Ok(())
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut out = Out::new();
        out.long(self.lifetime);
        out.long(self.add);
        out.prefixed(&self.nonce, 1)?;
        out.prefixed(&self.ticket, 2)?;
        out.extensions(&self.extensions, 0)?;
        Ok(out.finish())
    }
}
