use super::{GRANULARITY, Mark, Outcome, Recovery, Sent, Space};
use crate::error::Error;
use crate::frame::Ack;
use std::collections::BTreeMap;

const THRESHOLD: u64 = 3;

fn spans(ack: &Ack) -> Vec<(u64, u64)> {
    let mut high = ack.largest;
    let mut low = high - ack.first;
    let mut out = vec![(low, high)];
    for (gap, length) in &ack.ranges {
        high = low - gap - 2;
        low = high - length;
        out.push((low, high));
    }
    out
}

impl Recovery {
    pub fn acked(&mut self, now: u64, space: Space, ack: &Ack) -> Result<Outcome, Error> {
        ack.check()?;
        if space == Space::Handshake {
            self.validated = true;
        }
        let lane = &mut self.lanes[space.slot()];
        lane.largest = lane.largest.max(Some(ack.largest));
        let mut found = Vec::new();
        for (low, high) in spans(ack) {
            let mut tail = lane.sent.split_off(&low);
            let rest = tail.split_off(&high.saturating_add(1));
            found.extend(tail.into_values());
            lane.sent.extend(rest);
        }
        found.sort_by_key(|packet| packet.number);
        let Some(top) = found.last() else {
            return Ok(Outcome::default());
        };
        if top.number == ack.largest && found.iter().any(|packet| packet.eliciting) {
            let latest = now.saturating_sub(top.time);
            let delay = self.scaled(space, ack);
            self.rtt.update(now, latest, delay);
        }
        let lost = self.detect(now, space);
        if self.validated {
            self.pto = 0;
        }
        self.arm(now);
        Ok(Outcome { acked: found, lost })
    }

    fn scaled(&self, space: Space, ack: &Ack) -> u64 {
        if space == Space::Initial {
            return 0;
        }
        let raw = ack.delay.saturating_mul(1 << self.exponent.min(20));
        if self.confirmed {
            raw.min(self.delay)
        } else {
            raw
        }
    }

    pub(super) fn detect(&mut self, now: u64, space: Space) -> Vec<Sent> {
        let base = self.rtt.latest().max(self.rtt.smooth());
        let window = (base.saturating_mul(9) / 8).max(GRANULARITY);
        let lane = &mut self.lanes[space.slot()];
        lane.loss = None;
        let Some(largest) = lane.largest else {
            return Vec::new();
        };
        let mut gone = Vec::new();
        for (number, packet) in lane.sent.range(..=largest) {
            let late = packet.time.saturating_add(window);
            if late <= now || largest >= number + THRESHOLD {
                gone.push(*number);
            } else {
                lane.loss = Some(lane.loss.map_or(late, |least| least.min(late)));
            }
        }
        gone.iter()
            .filter_map(|number| lane.sent.remove(number))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Testing,
    Unknown,
    Capable,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub status: Status,
    pub congested: bool,
}

#[derive(Debug, Clone, Default)]
struct Book {
    marked: BTreeMap<u64, Mark>,
    sent: [u64; 2],
    base: [u64; 3],
    largest: Option<u64>,
}

impl Book {
    fn advances(&self, largest: u64) -> bool {
        self.largest.is_none_or(|top| largest > top)
    }

    fn newly(&self, ack: &Ack) -> Vec<(u64, Mark)> {
        let mut found = Vec::new();
        for (low, high) in spans(ack) {
            let inside = self.marked.range(low..=high);
            found.extend(inside.map(|(number, mark)| (*number, *mark)));
        }
        found
    }

    fn sound(&self, counts: [u64; 3], newly: [u64; 2]) -> bool {
        let mut growth = [0u64; 3];
        for (at, step) in growth.iter_mut().enumerate() {
            let Some(value) = counts[at].checked_sub(self.base[at]) else {
                return false;
            };
            *step = value;
        }
        let bad = |at: usize| {
            let owed = growth[at].saturating_add(growth[2]) < newly[at];
            owed || counts[at] > self.sent[at]
        };
        !bad(0) && !bad(1)
    }

    fn judge(&self, ack: &Ack, found: &[(u64, Mark)]) -> Option<[u64; 3]> {
        let count = |mark: Mark| found.iter().filter(|(_, kind)| *kind == mark).count() as u64;
        let newly = [count(Mark::Ect0), count(Mark::Ect1)];
        let Some(ecn) = &ack.ecn else {
            return found.is_empty().then_some(self.base);
        };
        let counts = [ecn.ect0, ecn.ect1, ecn.ce];
        self.sound(counts, newly).then_some(counts)
    }
}

fn index(mark: Mark) -> usize {
    usize::from(mark == Mark::Ect1)
}

#[derive(Debug, Clone)]
pub struct Marking {
    code: Mark,
    limit: u64,
    status: Status,
    issued: u64,
    total: u64,
    lost: u64,
    seen: u64,
    books: [Book; 3],
}

impl Marking {
    pub fn new(limit: u64, ect1: bool) -> Self {
        let status = if limit == 0 {
            Status::Unknown
        } else {
            Status::Testing
        };
        Self {
            code: if ect1 { Mark::Ect1 } else { Mark::Ect0 },
            limit,
            status,
            issued: 0,
            total: 0,
            lost: 0,
            seen: 0,
            books: Default::default(),
        }
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn send(&mut self, space: Space, number: u64) -> Mark {
        if !matches!(self.status, Status::Testing | Status::Capable) {
            return Mark::Plain;
        }
        let book = &mut self.books[space.slot()];
        book.marked.insert(number, self.code);
        book.sent[index(self.code)] += 1;
        self.total += 1;
        if self.status == Status::Testing {
            self.issued += 1;
        }
        if self.status == Status::Testing && self.issued >= self.limit {
            self.status = if self.seen > 0 {
                Status::Capable
            } else {
                Status::Unknown
            };
        }
        self.code
    }

    pub fn acked(&mut self, space: Space, ack: &Ack) -> Report {
        let quiet = Report {
            status: self.status,
            congested: false,
        };
        if ack.check().is_err() || self.status == Status::Failed {
            return quiet;
        }
        let book = &mut self.books[space.slot()];
        if !book.advances(ack.largest) {
            return quiet;
        }
        let found = book.newly(ack);
        let Some(counts) = book.judge(ack, &found) else {
            self.status = Status::Failed;
            return Report {
                status: Status::Failed,
                congested: false,
            };
        };
        let congested = counts[2] > book.base[2];
        book.largest = Some(ack.largest);
        book.base = counts;
        for (number, _) in &found {
            book.marked.remove(number);
        }
        self.seen += found.len() as u64;
        if self.status == Status::Unknown && !found.is_empty() {
            self.status = Status::Capable;
        }
        Report {
            status: self.status,
            congested,
        }
    }

    pub fn lost(&mut self, space: Space, numbers: &[u64]) -> Status {
        let book = &mut self.books[space.slot()];
        let gone = numbers
            .iter()
            .filter(|number| book.marked.remove(number).is_some())
            .count();
        self.lost += gone as u64;
        let silent = self.seen == 0 && self.total > 0;
        if self.status == Status::Unknown && silent && self.lost >= self.total {
            self.status = Status::Failed;
        }
        self.status
    }

    pub fn discard(&mut self, space: Space) {
        let book = &mut self.books[space.slot()];
        self.total -= book.marked.len() as u64;
        book.marked.clear();
    }

    pub fn restart(&mut self) {
        self.total = self.books.iter().map(|book| book.marked.len() as u64).sum();
        self.issued = 0;
        self.lost = 0;
        self.seen = 0;
        self.status = if self.limit == 0 {
            Status::Unknown
        } else {
            Status::Testing
        };
    }
}
