use crate::fault::Fault;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowance {
    limit: u64,
    window: u64,
    highest: u64,
    consumed: u64,
    fault: Fault,
}

impl Allowance {
    pub fn new(limit: u64, fault: Fault) -> Self {
        Self {
            limit,
            window: limit,
            highest: 0,
            consumed: 0,
            fault,
        }
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }

    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    pub fn accept(&mut self, end: u64) -> Result<u64, Fault> {
        if end > self.limit {
            return Err(self.fault);
        }
        let fresh = end.saturating_sub(self.highest);
        self.highest = self.highest.max(end);
        Ok(fresh)
    }

    pub fn charge(&mut self, count: u64) -> Result<u64, Fault> {
        self.accept(self.highest.saturating_add(count))
    }

    pub fn consume(&mut self, count: u64) {
        self.consumed = self.consumed.saturating_add(count).min(self.highest);
    }

    pub fn grant(&mut self) -> Option<u64> {
        let target = self.consumed.saturating_add(self.window);
        if target <= self.limit || target - self.limit < self.window / 2 {
            return None;
        }
        self.limit = target;
        Some(target)
    }
}
