use crate::error::Error;
use crate::packet::ident;
use crate::packet::negotiation::Negotiation;
use wire::Reader;

const LIMIT: usize = 255;
const SMALLEST: usize = 1200;
const UNUSED: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Abandon,
    Ignore,
}

#[derive(Debug, Clone)]
pub struct Client {
    version: u32,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    done: bool,
}

impl Client {
    pub fn new(version: u32, dcid: &[u8], scid: &[u8]) -> Self {
        Self {
            version,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            done: false,
        }
    }

    pub fn processed(&mut self) {
        self.done = true;
    }

    pub fn receive(&mut self, packet: &Negotiation) -> Verdict {
        let echoed = packet.dcid == self.scid && packet.scid == self.dcid;
        if self.done || !echoed || packet.versions.contains(&self.version) {
            return Verdict::Ignore;
        }
        self.done = true;
        Verdict::Abandon
    }
}

fn reserved(version: u32) -> bool {
    version & 0x0f0f_0f0f == 0x0a0a_0a0a
}

pub fn answer(
    datagram: &[u8],
    supported: &[u32],
    grease: u32,
) -> Result<Option<Negotiation>, Error> {
    let mut reader = Reader::new(datagram);
    if reader.byte()? & 0x80 == 0 {
        return Ok(None);
    }
    let version = ident::word(&mut reader)?;
    let dcid = ident::take(&mut reader, LIMIT)?;
    let scid = ident::take(&mut reader, LIMIT)?;
    if version == 0 || supported.contains(&version) || datagram.len() < SMALLEST {
        return Ok(None);
    }
    let mut versions = supported.to_vec();
    if reserved(grease) && !supported.contains(&grease) {
        versions.push(grease);
    }
    Ok(Some(Negotiation {
        unused: UNUSED,
        dcid: scid,
        scid: dcid,
        versions,
    }))
}
