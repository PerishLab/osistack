use crate::fault::Fault;
use crate::frame::Frame;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

#[derive(Debug, Clone)]
pub struct Issued {
    limit: u64,
    zero: bool,
    next: u64,
    prior: u64,
    live: BTreeMap<u64, Vec<u8>>,
}

impl Issued {
    pub fn new(cid: Vec<u8>, limit: u64) -> Self {
        Self {
            limit,
            zero: cid.is_empty(),
            next: 1,
            prior: 0,
            live: BTreeMap::from([(0, cid)]),
        }
    }

    pub fn issue(&mut self, cid: Vec<u8>, token: [u8; 16], retire: u64) -> Result<Frame, Refused> {
        let sequence = self.next;
        let retire = retire.clamp(self.prior, sequence);
        let shape = cid.is_empty() || cid.len() > 20;
        let clash = self.zero || self.find(&cid).is_some();
        let kept = self.live.range(retire..).count() as u64 + 1;
        if shape || clash || kept > self.limit {
            return Err(Refused);
        }
        self.next += 1;
        self.prior = retire;
        self.live.insert(sequence, cid.clone());
        Ok(Frame::Issue {
            sequence,
            retire,
            cid,
            token,
        })
    }

    pub fn retire(&mut self, sequence: u64, dcid: &[u8]) -> Result<bool, Fault> {
        let using = self.live.get(&sequence).is_some_and(|cid| cid == dcid);
        if sequence >= self.next || using || self.zero {
            return Err(Fault::Protocol);
        }
        Ok(self.live.remove(&sequence).is_some())
    }

    pub fn find(&self, cid: &[u8]) -> Option<u64> {
        self.live
            .iter()
            .find(|(_, held)| held.as_slice() == cid)
            .map(|(sequence, _)| *sequence)
    }

    pub fn live(&self) -> Vec<u64> {
        self.live.keys().copied().collect()
    }

    pub fn active(&self) -> usize {
        self.live.range(self.prior..).count()
    }
}
