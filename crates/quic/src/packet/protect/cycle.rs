use super::keys::Keys;
use super::seal::Opened;
use crate::error::Error;

pub struct Cycle {
    current: Keys,
    previous: Option<Keys>,
    phase: bool,
}

impl Cycle {
    pub fn new(keys: Keys) -> Self {
        Self {
            current: keys,
            previous: None,
            phase: false,
        }
    }

    pub fn phase(&self) -> bool {
        self.phase
    }

    pub fn advance(&mut self) -> Result<(), Error> {
        let next = self.current.update()?;
        self.previous = Some(self.current.clone());
        self.current = next;
        self.phase = !self.phase;
        Ok(())
    }

    pub fn protect(&self, number: u64, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let first = *header.first().ok_or(Error::Length)?;
        if first & 0x80 == 0 && (first & 0x04 != 0) != self.phase {
            return Err(Error::Kind);
        }
        self.current.protect(number, header, payload)
    }

    pub fn unprotect(
        &self,
        packet: &[u8],
        offset: usize,
        largest: Option<u64>,
    ) -> Result<Opened, Error> {
        let first = *packet.first().ok_or(Error::Length)?;
        if first & 0x80 != 0 {
            return self.current.unprotect(packet, offset, largest);
        }
        let phase = self.current.phase(packet, offset)?;
        let keys = match (phase == self.phase, &self.previous) {
            (true, _) => &self.current,
            (false, Some(previous)) => previous,
            (false, None) => return Err(Error::Crypto(crypto::Error::Auth)),
        };
        keys.unprotect(packet, offset, largest)
    }
}
