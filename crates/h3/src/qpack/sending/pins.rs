use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct Pins {
    counts: BTreeMap<u64, usize>,
}

impl Pins {
    pub fn hold(&mut self, absolute: u64) {
        *self.counts.entry(absolute).or_insert(0) += 1;
    }

    pub fn release(&mut self, absolute: u64) {
        let Some(count) = self.counts.get_mut(&absolute) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            self.counts.remove(&absolute);
        }
    }

    pub fn held(&self, absolute: u64) -> bool {
        self.counts.contains_key(&absolute)
    }

    pub fn within(&self, from: u64, count: u64) -> bool {
        self.counts
            .range(from..from.saturating_add(count))
            .next()
            .is_some()
    }
}
