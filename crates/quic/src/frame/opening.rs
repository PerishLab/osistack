use crate::error::Error;
use crate::frame::Frame;
use crate::packet::{Initial, Kind, Long, Number};

pub struct Opening {
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
}

impl Opening {
    pub fn write(&self, hello: &[u8]) -> Result<Vec<u8>, Error> {
        if hello.is_empty() {
            return Err(Error::Length);
        }
        let number = Number::new(0, None)?;
        let mut payload = Frame::Crypto {
            offset: 0,
            data: hello.to_vec(),
        }
        .write()?;
        loop {
            let packet = self.protect(&number, &payload)?;
            if packet.len() >= 1200 {
                return Ok(packet);
            }
            payload.extend(vec![0u8; 1200 - packet.len()]);
        }
    }

    fn protect(&self, number: &Number, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let length = (number.length + payload.len() + 16) as u64;
        let long = Long {
            kind: Kind::Initial,
            dcid: self.dcid.clone(),
            scid: self.scid.clone(),
            token: self.token.clone(),
            length,
            offset: 0,
        };
        let keys = Initial::new(&self.dcid)?;
        keys.client.protect(0, &long.write(number)?, payload)
    }
}
