use super::allowance::Allowance;
use crate::fault::Fault;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    allowance: Allowance,
    last: Option<u64>,
}

impl Inbound {
    pub fn new(limit: u64) -> Self {
        Self {
            allowance: Allowance::new(limit, Fault::Flow),
            last: None,
        }
    }

    pub fn last(&self) -> Option<u64> {
        self.last
    }

    pub fn allowance(&self) -> &Allowance {
        &self.allowance
    }

    pub fn data(&mut self, offset: u64, length: u64, fin: bool) -> Result<u64, Fault> {
        let end = offset.saturating_add(length);
        let past = self.last.is_some_and(|last| end > last);
        let short = fin && end < self.allowance.highest();
        if past || short {
            return Err(Fault::Final);
        }
        let fresh = self.allowance.accept(end)?;
        if fin {
            self.last = Some(end);
        }
        Ok(fresh)
    }

    pub fn reset(&mut self, size: u64) -> Result<u64, Fault> {
        self.data(size, 0, true)
    }

    pub fn consume(&mut self, count: u64) {
        self.allowance.consume(count);
    }

    pub fn grant(&mut self) -> Option<u64> {
        self.allowance.grant()
    }
}
