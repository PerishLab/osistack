use super::Space;
use crate::frame::{Ack, Ecn};
use std::collections::BTreeMap;

const SHIFT: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Plain,
    Ect0,
    Ect1,
    Ce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    Fresh,
    Repeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    pub number: u64,
    pub time: u64,
    pub eliciting: bool,
    pub mark: Mark,
}

#[derive(Debug, Clone)]
struct Tracker {
    delay: u64,
    exponent: u64,
    limit: usize,
    ranges: BTreeMap<u64, u64>,
    floor: u64,
    top: Option<(u64, u64)>,
    high: Option<u64>,
    count: u32,
    due: Option<u64>,
    dirty: bool,
    marks: [u64; 3],
    carried: BTreeMap<u64, u64>,
}

impl Tracker {
    fn new(delay: u64, exponent: u64, limit: usize) -> Self {
        Self {
            delay,
            exponent,
            limit: limit.max(1),
            ranges: BTreeMap::new(),
            floor: 0,
            top: None,
            high: None,
            count: 0,
            due: None,
            dirty: false,
            marks: [0; 3],
            carried: BTreeMap::new(),
        }
    }

    fn reset(&mut self) {
        *self = Self::new(self.delay, self.exponent, self.limit);
    }

    fn start(&self, number: u64) -> u64 {
        self.ranges
            .range(..=number)
            .next_back()
            .map_or(number, |(low, _)| *low)
    }

    fn insert(&mut self, number: u64) -> bool {
        if number < self.floor {
            return false;
        }
        let below = self.ranges.range(..=number).next_back();
        let start = match below.map(|(low, high)| (*low, *high)) {
            Some((_, high)) if number <= high => return false,
            Some((low, high)) if number == high + 1 => low,
            _ => number,
        };
        self.ranges.insert(start, number);
        if let Some(end) = self.ranges.remove(&(number + 1)) {
            self.ranges.insert(start, end);
        }
        while self.ranges.len() > self.limit {
            if let Some((_, high)) = self.ranges.pop_first() {
                self.floor = high + 1;
            }
        }
        number >= self.floor
    }

    fn tally(&mut self, mark: Mark) {
        let slot = match mark {
            Mark::Plain => return,
            Mark::Ect0 => 0,
            Mark::Ect1 => 1,
            Mark::Ce => 2,
        };
        self.marks[slot] = self.marks[slot].saturating_add(1);
    }

    fn ragged(&self, number: u64) -> bool {
        let Some(high) = self.high else {
            return false;
        };
        number < high || self.start(number) > high + 1
    }

    fn prompt(&self, arrival: &Arrival) -> bool {
        self.delay == 0 || arrival.mark == Mark::Ce
    }

    fn urgent(&self, arrival: &Arrival) -> bool {
        self.prompt(arrival) || self.count >= 1 || self.ragged(arrival.number)
    }

    fn elicit(&mut self, arrival: &Arrival) {
        let at = if self.urgent(arrival) {
            arrival.time
        } else {
            arrival.time.saturating_add(self.delay)
        };
        self.due = Some(self.due.map_or(at, |old| old.min(at)));
        self.count += 1;
        self.high = self.high.max(Some(arrival.number));
    }

    fn receive(&mut self, arrival: &Arrival) -> Seen {
        if !self.insert(arrival.number) {
            return Seen::Repeat;
        }
        self.dirty = true;
        if self.top.is_none_or(|(top, _)| arrival.number > top) {
            self.top = Some((arrival.number, arrival.time));
        }
        self.tally(arrival.mark);
        if arrival.eliciting {
            self.elicit(arrival);
        }
        Seen::Fresh
    }

    fn counts(&self) -> Option<Ecn> {
        if self.marks.iter().sum::<u64>() == 0 {
            return None;
        }
        Some(Ecn {
            ect0: self.marks[0],
            ect1: self.marks[1],
            ce: self.marks[2],
        })
    }

    fn frame(&mut self, now: u64) -> Option<Ack> {
        if !self.dirty {
            return None;
        }
        let (largest, time) = self.top?;
        let mut spans = self.ranges.iter().rev();
        let (low, high) = spans.next()?;
        let first = high - low;
        let mut under = *low;
        let mut ranges = Vec::new();
        for (low, high) in spans {
            ranges.push((under - high - 2, high - low));
            under = *low;
        }
        self.dirty = false;
        self.count = 0;
        self.due = None;
        Some(Ack {
            largest,
            delay: now.saturating_sub(time) >> self.exponent.min(SHIFT),
            first,
            ranges,
            ecn: self.counts(),
        })
    }

    fn carry(&mut self, packet: u64, largest: u64) {
        self.carried.insert(packet, largest);
        while self.carried.len() > self.limit {
            self.carried.pop_first();
        }
    }

    fn confirm(&mut self, packet: u64) {
        let Some(largest) = self.carried.remove(&packet) else {
            return;
        };
        self.carried = self.carried.split_off(&packet);
        let Some((top, _)) = self.top else {
            return;
        };
        self.floor = self.floor.max(largest.saturating_add(1).min(top));
        let mut tail = self.ranges.split_off(&self.floor);
        let kept = self
            .ranges
            .pop_last()
            .filter(|(_, high)| *high >= self.floor);
        if let Some((_, high)) = kept {
            tail.insert(self.floor, high);
        }
        self.ranges = tail;
    }
}

#[derive(Debug, Clone)]
pub struct Received {
    lanes: [Tracker; 3],
}

impl Received {
    pub fn new(delay: u64, exponent: u64, limit: usize) -> Self {
        Self {
            lanes: [
                Tracker::new(0, exponent, limit),
                Tracker::new(0, exponent, limit),
                Tracker::new(delay, exponent, limit),
            ],
        }
    }

    pub fn receive(&mut self, space: Space, arrival: Arrival) -> Seen {
        self.lanes[space.slot()].receive(&arrival)
    }

    pub fn deadline(&self, space: Space) -> Option<u64> {
        self.lanes[space.slot()].due
    }

    pub fn next(&self) -> Option<u64> {
        self.lanes.iter().filter_map(|lane| lane.due).min()
    }

    pub fn frame(&mut self, space: Space, now: u64) -> Option<Ack> {
        self.lanes[space.slot()].frame(now)
    }

    pub fn carried(&mut self, space: Space, packet: u64, largest: u64) {
        self.lanes[space.slot()].carry(packet, largest);
    }

    pub fn confirmed(&mut self, space: Space, packet: u64) {
        self.lanes[space.slot()].confirm(packet);
    }

    pub fn discard(&mut self, space: Space) {
        self.lanes[space.slot()].reset();
    }

    pub fn ranges(&self, space: Space) -> Vec<(u64, u64)> {
        let lane = &self.lanes[space.slot()];
        lane.ranges
            .iter()
            .map(|(low, high)| (*low, *high))
            .collect()
    }
}
