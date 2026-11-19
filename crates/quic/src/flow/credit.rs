#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    limit: u64,
    used: u64,
    shown: Option<u64>,
}

impl Credit {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            shown: None,
        }
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn room(&self) -> u64 {
        self.limit - self.used
    }

    pub fn take(&mut self, want: u64) -> u64 {
        let grant = want.min(self.room());
        self.used += grant;
        grant
    }

    pub fn share(&mut self, total: &mut Credit, want: u64) -> u64 {
        let grant = want.min(self.room()).min(total.room());
        self.used += grant;
        total.used += grant;
        grant
    }

    pub fn raise(&mut self, limit: u64) -> bool {
        if limit <= self.limit {
            return false;
        }
        self.limit = limit;
        true
    }

    pub fn stalled(&mut self) -> Option<u64> {
        if self.room() != 0 || self.shown == Some(self.limit) {
            return None;
        }
        self.shown = Some(self.limit);
        Some(self.limit)
    }
}
