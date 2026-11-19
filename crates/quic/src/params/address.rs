use crate::error::Error;
use crate::field::Cursor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub v4: [u8; 4],
    pub port4: u16,
    pub v6: [u8; 16],
    pub port6: u16,
    pub cid: Vec<u8>,
    pub token: [u8; 16],
}

impl Address {
    pub fn read(value: &[u8]) -> Result<Self, Error> {
        let mut reader = Cursor::new(value);
        let v4 = reader.array()?;
        let port4 = u16::from_be_bytes(reader.array()?);
        let v6 = reader.array()?;
        let port6 = u16::from_be_bytes(reader.array()?);
        let cid = reader.cid()?;
        let token = reader.array()?;
        if reader.left() > 0 {
            return Err(Error::Length);
        }
        Ok(Self {
            v4,
            port4,
            v6,
            port6,
            cid,
            token,
        })
    }

    pub fn write(&self) -> Result<Vec<u8>, Error> {
        if !(1..=20).contains(&self.cid.len()) {
            return Err(Error::Length);
        }
        let mut bytes = self.v4.to_vec();
        bytes.extend(self.port4.to_be_bytes());
        bytes.extend(self.v6);
        bytes.extend(self.port6.to_be_bytes());
        bytes.push(self.cid.len() as u8);
        bytes.extend(&self.cid);
        bytes.extend(self.token);
        Ok(bytes)
    }
}
