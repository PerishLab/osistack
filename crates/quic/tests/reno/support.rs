use quic::{Ack, Ecn, Marking, Report, Rtt, Sent, Space, Status};
use std::collections::BTreeSet;

pub fn packet(number: u64, time: u64) -> Sent {
    Sent {
        number,
        time,
        size: 1200,
        eliciting: true,
        flight: true,
    }
}

pub fn quiet(number: u64, time: u64) -> Sent {
    Sent {
        number,
        time,
        size: 40,
        eliciting: false,
        flight: false,
    }
}

pub fn measured() -> Rtt {
    let mut rtt = Rtt::new();
    rtt.update(100_000, 100_000, 0);
    rtt
}

pub fn strip(first: u64, count: u64, oldest: u64, newest: u64) -> Vec<Sent> {
    (0..count)
        .map(|step| {
            let time = match step {
                0 => oldest,
                last if last + 1 == count => newest,
                middle => oldest + middle,
            };
            packet(first + step, time)
        })
        .collect()
}

pub fn frame(seen: &BTreeSet<u64>) -> Ack {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &number in seen {
        match runs.last_mut() {
            Some((_, high)) if *high + 1 == number => *high = number,
            _ => runs.push((number, number)),
        }
    }
    runs.reverse();
    let (low, high) = runs[0];
    let mut ranges = Vec::new();
    let mut floor = low;
    for &(low, high) in &runs[1..] {
        ranges.push((floor - high - 2, high - low));
        floor = low;
    }
    Ack {
        largest: high,
        delay: 0,
        first: high - low,
        ranges,
        ecn: None,
    }
}

pub struct Dice(u64);

impl Dice {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }
}

pub fn reply(largest: u64, first: u64, ecn: Option<Ecn>) -> Ack {
    Ack {
        largest,
        delay: 0,
        first,
        ranges: Vec::new(),
        ecn,
    }
}

pub fn counts(ect0: u64, ect1: u64, ce: u64) -> Option<Ecn> {
    Some(Ecn { ect0, ect1, ce })
}

pub fn only(ect0: u64) -> Option<Ecn> {
    counts(ect0, 0, 0)
}

pub fn armed(limit: u64, count: u64) -> Marking {
    let mut marking = Marking::new(limit, false);
    for number in 0..count {
        marking.send(Space::Data, number);
    }
    marking
}

pub fn verdict(status: Status, congested: bool) -> Report {
    Report { status, congested }
}
