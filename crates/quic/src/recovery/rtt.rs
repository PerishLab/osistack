pub const GRANULARITY: u64 = 1_000;
pub const INITIAL: u64 = 333_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rtt {
    latest: u64,
    smooth: u64,
    vary: u64,
    floor: u64,
    first: Option<u64>,
}

impl Default for Rtt {
    fn default() -> Self {
        Self::new()
    }
}

impl Rtt {
    pub fn new() -> Self {
        Self {
            latest: 0,
            smooth: INITIAL,
            vary: INITIAL / 2,
            floor: 0,
            first: None,
        }
    }

    pub fn update(&mut self, now: u64, latest: u64, delay: u64) {
        self.latest = latest;
        if self.first.is_none() {
            self.first = Some(now);
            self.floor = latest;
            self.smooth = latest;
            self.vary = latest / 2;
            return;
        }
        self.floor = self.floor.min(latest);
        let adjusted = if latest >= self.floor.saturating_add(delay) {
            latest - delay
        } else {
            latest
        };
        let spread = self.smooth.abs_diff(adjusted);
        self.vary = self.vary.saturating_mul(3).saturating_add(spread) / 4;
        self.smooth = self.smooth.saturating_mul(7).saturating_add(adjusted) / 8;
    }

    pub fn latest(&self) -> u64 {
        self.latest
    }

    pub fn smooth(&self) -> u64 {
        self.smooth
    }

    pub fn vary(&self) -> u64 {
        self.vary
    }

    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn first(&self) -> Option<u64> {
        self.first
    }
}
