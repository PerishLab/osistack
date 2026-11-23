use std::collections::BTreeMap;

use crate::error::Error;
use crate::frame::Frame;
use crate::packet::{Header, Initial, Keys, Kind};
use crypto::{Aead, Hash};

struct Gather {
    parts: BTreeMap<u64, u8>,
    body: Vec<u8>,
}

impl Gather {
    fn new() -> Self {
        Self {
            parts: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    fn push(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        for (index, byte) in data.iter().enumerate() {
            let at = offset.checked_add(index as u64).ok_or(Error::Length)?;
            if at < self.body.len() as u64 {
                if self.body[at as usize] != *byte {
                    return Err(Error::Value);
                }
                continue;
            }
            if let Some(old) = self.parts.insert(at, *byte)
                && old != *byte
            {
                return Err(Error::Value);
            }
        }
        self.pull();
        Ok(())
    }

    fn pull(&mut self) {
        while let Some(&byte) = self.parts.get(&(self.body.len() as u64)) {
            let at = self.body.len() as u64;
            self.parts.remove(&at);
            self.body.push(byte);
        }
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

fn feed(gather: &mut Gather, payload: &[u8]) -> Result<(), Error> {
    for frame in Frame::all(payload)? {
        if let Frame::Crypto { offset, data } = frame {
            gather.push(offset, &data)?;
        }
    }
    Ok(())
}

fn opened(keys: &Keys, packet: &[u8], local: usize, kind: Kind) -> Result<(u64, Vec<u8>), Error> {
    let Header::Long(long) = Header::parse(packet, local)? else {
        return Err(Error::Kind);
    };
    if long.kind != kind {
        return Err(Error::Kind);
    }
    let size = long.size()?;
    let packet = packet.get(..size).ok_or(Error::Length)?;
    let opened = keys.unprotect(packet, long.offset, None)?;
    Ok((opened.number, opened.payload))
}

pub struct Hearing {
    keys: Keys,
    local: usize,
    gather: Gather,
}

impl Hearing {
    pub fn new(dcid: &[u8], local: usize) -> Result<Self, Error> {
        Ok(Self {
            keys: Initial::new(dcid)?.server,
            local,
            gather: Gather::new(),
        })
    }

    pub fn ingest(&mut self, packet: &[u8]) -> Result<u64, Error> {
        let (number, payload) = opened(&self.keys, packet, self.local, Kind::Initial)?;
        feed(&mut self.gather, &payload)?;
        Ok(number)
    }

    pub fn crypto(&self) -> &[u8] {
        self.gather.body()
    }
}

pub struct Handshake {
    pub client: Keys,
    pub server: Keys,
    gather: Gather,
}

impl Handshake {
    pub fn new(hash: Hash, aead: Aead, client: &[u8], server: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            client: Keys::derive(hash, aead, client)?,
            server: Keys::derive(hash, aead, server)?,
            gather: Gather::new(),
        })
    }

    pub fn ingest(&mut self, packet: &[u8], local: usize) -> Result<u64, Error> {
        let (number, payload) = opened(&self.server, packet, local, Kind::Handshake)?;
        feed(&mut self.gather, &payload)?;
        Ok(number)
    }

    pub fn crypto(&self) -> &[u8] {
        self.gather.body()
    }
}
