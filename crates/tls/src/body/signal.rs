use crate::error::Error;
use crate::field::Scan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Update {
    pub request: bool,
}

impl Update {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let request = match scan.byte()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Value),
        };
        scan.end()?;
        Ok(Self { request })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![u8::from(self.request)])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct End;

impl End {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        Scan::new(body).end()?;
        Ok(Self)
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: u8,
    pub description: u8,
}

impl Alert {
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut scan = Scan::new(body);
        let level = scan.byte()?;
        let description = scan.byte()?;
        scan.end()?;
        Ok(Self { level, description })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        Ok(vec![self.level, self.description])
    }
}
