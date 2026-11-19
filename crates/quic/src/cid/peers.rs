use crate::fault::Fault;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
struct Entry {
    cid: Vec<u8>,
    token: Option<[u8; 16]>,
    used: bool,
}

#[derive(Debug, Clone)]
pub struct Peers {
    limit: u64,
    zero: bool,
    prior: u64,
    current: u64,
    live: BTreeMap<u64, Entry>,
    gone: BTreeSet<u64>,
}

impl Peers {
    pub fn new(cid: Vec<u8>, token: Option<[u8; 16]>, limit: u64) -> Self {
        Self {
            limit,
            zero: cid.is_empty(),
            prior: 0,
            current: 0,
            live: BTreeMap::from([(
                0,
                Entry {
                    cid,
                    token,
                    used: true,
                },
            )]),
            gone: BTreeSet::new(),
        }
    }

    pub fn receive(
        &mut self,
        sequence: u64,
        retire: u64,
        cid: &[u8],
        token: [u8; 16],
    ) -> Result<Vec<u64>, Fault> {
        let mut next = self.clone();
        let out = next.apply(sequence, retire, cid, token)?;
        *self = next;
        Ok(out)
    }

    fn apply(
        &mut self,
        sequence: u64,
        retire: u64,
        cid: &[u8],
        token: [u8; 16],
    ) -> Result<Vec<u64>, Fault> {
        if retire > sequence || cid.is_empty() || cid.len() > 20 {
            return Err(Fault::Encoding);
        }
        let held = self.live.get(&sequence);
        let differs = held.is_some_and(|entry| entry.cid != cid || entry.token != Some(token));
        let repeats = self
            .live
            .iter()
            .any(|(seq, entry)| *seq != sequence && entry.cid == cid);
        if self.zero || differs || repeats {
            return Err(Fault::Protocol);
        }
        if held.is_none() && !self.gone.contains(&sequence) {
            let entry = Entry {
                cid: cid.to_vec(),
                token: Some(token),
                used: false,
            };
            self.live.insert(sequence, entry);
        }
        self.prior = self.prior.max(retire);
        let out = self.expire();
        if self.live.len() as u64 > self.limit {
            return Err(Fault::Ids);
        }
        self.settle()?;
        Ok(out)
    }

    fn expire(&mut self) -> Vec<u64> {
        let due: Vec<u64> = self.live.range(..self.prior).map(|(seq, _)| *seq).collect();
        for seq in &due {
            self.live.remove(seq);
            self.gone.insert(*seq);
        }
        due
    }

    fn settle(&mut self) -> Result<(), Fault> {
        if self.live.contains_key(&self.current) {
            return Ok(());
        }
        let (seq, entry) = self.live.iter_mut().next().ok_or(Fault::Protocol)?;
        entry.used = true;
        self.current = *seq;
        Ok(())
    }

    pub fn current(&self) -> (u64, &[u8]) {
        (self.current, &self.live[&self.current].cid)
    }

    pub fn fresh(&mut self) -> Option<(u64, Vec<u8>)> {
        let (seq, entry) = self.live.iter_mut().find(|(_, entry)| !entry.used)?;
        entry.used = true;
        Some((*seq, entry.cid.clone()))
    }

    pub fn rotate(&mut self) -> Option<u64> {
        let (seq, _) = self.fresh()?;
        let old = std::mem::replace(&mut self.current, seq);
        self.live.remove(&old);
        self.gone.insert(old);
        Some(old)
    }

    pub fn release(&mut self, sequence: u64) -> bool {
        if sequence == self.current || self.live.remove(&sequence).is_none() {
            return false;
        }
        self.gone.insert(sequence);
        true
    }

    pub fn matches(&self, token: &[u8; 16]) -> bool {
        self.live.values().any(|entry| entry.token == Some(*token))
    }

    pub fn active(&self) -> usize {
        self.live.len()
    }

    pub fn live(&self) -> Vec<u64> {
        self.live.keys().copied().collect()
    }
}
