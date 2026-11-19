fn micros(millis: u64) -> u64 {
    millis.saturating_mul(1000)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Idle {
    span: Option<u64>,
    last: u64,
    fresh: bool,
}

impl Idle {
    pub fn new(now: u64, local: u64, peer: u64) -> Self {
        let span = match (local, peer) {
            (0, 0) => None,
            (0, only) | (only, 0) => Some(micros(only)),
            (one, two) => Some(micros(one.min(two))),
        };
        Self {
            span,
            last: now,
            fresh: true,
        }
    }

    pub fn receive(&mut self, now: u64) {
        self.last = now;
        self.fresh = true;
    }

    pub fn send(&mut self, now: u64, eliciting: bool) {
        if eliciting && self.fresh {
            self.last = now;
            self.fresh = false;
        }
    }

    pub fn span(&self) -> Option<u64> {
        self.span
    }

    pub fn deadline(&self, pto: u64) -> Option<u64> {
        let span = self.span?;
        Some(self.last.saturating_add(span.max(pto.saturating_mul(3))))
    }

    pub fn expired(&self, now: u64, pto: u64) -> bool {
        self.deadline(pto).is_some_and(|due| now >= due)
    }
}
