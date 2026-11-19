use crate::error::Error;
use crate::extension::Extension;
use crate::field::{Out, Scan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub cert: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl Entry {
    fn read(scan: &mut Scan) -> Result<Self, Error> {
        let cert = scan.prefixed(3).map_err(Error::inner)?;
        if cert.is_empty() {
            return Err(Error::Length);
        }
        let extensions = scan.extensions(0).map_err(Error::inner)?;
        Ok(Self {
            cert: cert.to_vec(),
            extensions,
        })
    }

    fn put(&self, out: &mut Out) -> Result<(), Error> {
        if self.cert.is_empty() {
            return Err(Error::Length);
        }
        out.prefixed(&self.cert, 3)?;
        out.extensions(&self.extensions, 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub context: Vec<u8>,
    pub entries: Vec<Entry>,
}

impl Chain {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let context = scan.prefixed(1)?.to_vec();
        let list = scan.prefixed(3)?;
        scan.end()?;
        let mut inner = Scan::new(list);
        let mut entries = Vec::new();
        while inner.left() > 0 {
            entries.push(Entry::read(&mut inner)?);
        }
        Ok(Self { context, entries })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut list = Out::new();
        for entry in &self.entries {
            entry.put(&mut list)?;
        }
        let mut out = Out::new();
        out.prefixed(&self.context, 1)?;
        out.prefixed(&list.finish(), 3)?;
        Ok(out.finish())
    }
}
