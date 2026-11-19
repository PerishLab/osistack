#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amplify {
    received: u64,
    sent: u64,
    valid: bool,
}

impl Amplify {
    pub fn new(valid: bool) -> Self {
        Self {
            received: 0,
            sent: 0,
            valid,
        }
    }

    pub fn receive(&mut self, bytes: u64) {
        self.received = self.received.saturating_add(bytes);
    }

    pub fn room(&self) -> u64 {
        if self.valid {
            return u64::MAX;
        }
        self.received.saturating_mul(3).saturating_sub(self.sent)
    }

    pub fn send(&mut self, bytes: u64) -> bool {
        if !self.valid && bytes > self.room() {
            return false;
        }
        self.sent = self.sent.saturating_add(bytes);
        true
    }

    pub fn blocked(&self) -> bool {
        !self.valid && self.room() == 0
    }

    pub fn validate(&mut self) {
        self.valid = true;
    }

    pub fn validated(&self) -> bool {
        self.valid
    }
}
