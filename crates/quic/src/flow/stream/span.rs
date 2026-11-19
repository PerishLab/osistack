use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct Spans(BTreeMap<u64, u64>);

impl Spans {
    pub fn add(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let (mut low, mut high) = (start, end);
        let hits: Vec<u64> = self
            .0
            .range(..=end)
            .filter(|(_, stop)| **stop >= start)
            .map(|(from, _)| *from)
            .collect();
        for from in hits {
            let stop = self.0.remove(&from).unwrap_or(from);
            low = low.min(from);
            high = high.max(stop);
        }
        self.0.insert(low, high);
    }

    pub fn cut(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let hits: Vec<(u64, u64)> = self
            .0
            .range(..end)
            .filter(|(_, stop)| **stop > start)
            .map(|(from, stop)| (*from, *stop))
            .collect();
        for (from, stop) in hits {
            self.0.remove(&from);
            if from < start {
                self.0.insert(from, start);
            }
            if stop > end {
                self.0.insert(end, stop);
            }
        }
    }

    pub fn gaps(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut found = Vec::new();
        let mut cursor = start;
        for (from, stop) in self.0.range(..end) {
            if *stop <= cursor {
                continue;
            }
            if *from > cursor {
                found.push((cursor, *from));
            }
            cursor = cursor.max(*stop);
        }
        if cursor < end {
            found.push((cursor, end));
        }
        found
    }

    pub fn first(&self) -> Option<(u64, u64)> {
        self.0.iter().next().map(|(from, stop)| (*from, *stop))
    }
}
