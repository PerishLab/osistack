use super::span::Spans;
use crate::fault::Fault;
use crate::flow::Allowance;
use std::collections::BTreeMap;

const MAX: u64 = (1 << 62) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Open,
    Sized,
    Whole,
    Read,
    Reset,
    Gone,
}

#[derive(Debug, Clone)]
pub struct Receiving {
    allow: Allowance,
    have: Spans,
    chunks: BTreeMap<u64, Vec<u8>>,
    read: u64,
    size: Option<u64>,
    code: Option<u64>,
    gone: bool,
    stopped: bool,
}

impl Receiving {
    pub fn new(limit: u64) -> Self {
        Self {
            allow: Allowance::new(limit, Fault::Flow),
            have: Spans::default(),
            chunks: BTreeMap::new(),
            read: 0,
            size: None,
            code: None,
            gone: false,
            stopped: false,
        }
    }

    fn front(&self) -> u64 {
        match self.have.first() {
            Some((0, stop)) => stop,
            _ => 0,
        }
    }

    fn verify(&self, end: u64, fin: bool) -> Result<(), Fault> {
        match self.size {
            Some(size) if end > size || (fin && end != size) => Err(Fault::Final),
            None if fin && end < self.allow.highest() => Err(Fault::Final),
            _ => Ok(()),
        }
    }

    pub fn data(&mut self, offset: u64, bytes: &[u8], fin: bool) -> Result<u64, Fault> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= MAX)
            .ok_or(Fault::Encoding)?;
        self.verify(end, fin)?;
        if self.code.is_some() {
            return Ok(0);
        }
        let fresh = self.allow.accept(end)?;
        if fin {
            self.size = Some(end);
        }
        if self.stopped {
            self.have.add(offset, end);
            self.read = self.front();
            self.allow.consume(fresh);
        } else {
            self.store(offset, end, bytes);
        }
        Ok(fresh)
    }

    fn store(&mut self, offset: u64, end: u64, bytes: &[u8]) {
        let start = offset.max(self.read);
        for (from, to) in self.have.gaps(start, end) {
            let part = &bytes[(from - offset) as usize..(to - offset) as usize];
            self.chunks.insert(from, part.to_vec());
        }
        self.have.add(offset, end);
    }

    pub fn reset(&mut self, code: u64, size: u64) -> Result<u64, Fault> {
        let wrong = self.size.is_some_and(|known| known != size);
        if wrong || (self.size.is_none() && size < self.allow.highest()) {
            return Err(Fault::Final);
        }
        if self.code.is_some() {
            return Ok(0);
        }
        let fresh = self.allow.accept(size)?;
        if self.size == Some(size) && self.front() == size {
            return Ok(0);
        }
        self.size = Some(size);
        self.code = Some(code);
        self.chunks.clear();
        Ok(fresh)
    }

    pub fn read(&mut self, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        if self.code.is_some() || self.stopped {
            return out;
        }
        while out.len() < max {
            let Some(mut chunk) = self.chunks.remove(&self.read) else {
                break;
            };
            let take = chunk.len().min(max - out.len());
            let rest = chunk.split_off(take);
            if !rest.is_empty() {
                self.chunks.insert(self.read + take as u64, rest);
            }
            self.read += take as u64;
            out.extend(chunk);
        }
        self.allow.consume(out.len() as u64);
        out
    }

    pub fn broken(&mut self) -> Option<u64> {
        if self.gone {
            return None;
        }
        let code = self.code?;
        self.gone = true;
        Some(code)
    }

    pub fn stop(&mut self, code: u64) -> Option<u64> {
        let open = matches!(self.phase(), Phase::Open | Phase::Sized);
        if !open || self.stopped {
            return None;
        }
        self.stopped = true;
        self.chunks.clear();
        self.read = self.front();
        self.allow.consume(self.allow.highest());
        Some(code)
    }

    pub fn grant(&mut self) -> Option<u64> {
        self.allow.grant()
    }

    pub fn phase(&self) -> Phase {
        if self.gone {
            return Phase::Gone;
        }
        if self.code.is_some() {
            return Phase::Reset;
        }
        let Some(size) = self.size else {
            return Phase::Open;
        };
        if self.read == size {
            return Phase::Read;
        }
        if self.front() == size {
            return Phase::Whole;
        }
        Phase::Sized
    }

    pub fn highest(&self) -> u64 {
        self.allow.highest()
    }

    pub fn readable(&self) -> usize {
        if self.code.is_some() {
            return 0;
        }
        (self.front() - self.read) as usize
    }

    pub fn size(&self) -> Option<u64> {
        self.size
    }

    pub fn limit(&self) -> u64 {
        self.allow.limit()
    }
}
