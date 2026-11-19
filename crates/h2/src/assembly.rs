use crate::hpack::{Decoder, Header};
use crate::stream::{Code, Fault, Outcome};

pub const LIMIT: usize = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub stream: u32,
    pub fields: Vec<Header>,
    pub fin: bool,
}

#[derive(Debug, Clone)]
pub struct Assembly {
    stream: u32,
    fin: bool,
    bytes: Vec<u8>,
    verdict: Result<Outcome, Fault>,
}

impl Assembly {
    pub fn new(stream: u32, fin: bool, verdict: Result<Outcome, Fault>) -> Self {
        Self {
            stream,
            fin,
            bytes: Vec::new(),
            verdict,
        }
    }

    pub fn stream(&self) -> u32 {
        self.stream
    }

    pub fn push(&mut self, bytes: &[u8], cap: usize) -> Result<(), Fault> {
        if self.bytes.len().saturating_add(bytes.len()) > cap {
            return Err(Fault::Connection { code: Code::Calm });
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn finish(self, decoder: &mut Decoder) -> Result<(Outcome, Option<Block>), Fault> {
        let fields = decoder.decode(&self.bytes).map_err(|_| Fault::Connection {
            code: Code::Compression,
        })?;
        match self.verdict? {
            Outcome::Accept => {
                let block = Block {
                    stream: self.stream,
                    fields,
                    fin: self.fin,
                };
                Ok((Outcome::Accept, Some(block)))
            }
            Outcome::Discard => Ok((Outcome::Discard, None)),
        }
    }
}
