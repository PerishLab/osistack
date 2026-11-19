use crate::support::*;
use quic::{Allowance, Credit, Fault, Inbound};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Sent(u64),
    Stalled(u64),
    Blocked(u64),
    Stream(u64),
    Shared(u64),
}

struct Setup {
    stream: u64,
    shared: u64,
    size: u64,
    mtu: u64,
    rate: u64,
    delay: u64,
}

struct Pair {
    setup: Setup,
    out: Credit,
    all: Credit,
    inbound: Inbound,
    total: Allowance,
    wire: Vec<(u64, bool, u64)>,
    events: Vec<(u64, Event)>,
    sent: u64,
}

impl Pair {
    fn new(setup: Setup) -> Self {
        Self {
            out: Credit::new(setup.stream),
            all: Credit::new(setup.shared),
            inbound: Inbound::new(setup.stream),
            total: Allowance::new(setup.shared, Fault::Flow),
            wire: Vec::new(),
            events: Vec::new(),
            sent: 0,
            setup,
        }
    }

    fn deliver(&mut self, now: u64) {
        let due: Vec<(u64, bool, u64)> = self.wire.iter().filter(|w| w.0 <= now).cloned().collect();
        self.wire.retain(|w| w.0 > now);
        for (_, stream, limit) in due {
            if stream {
                self.out.raise(limit);
            } else {
                self.all.raise(limit);
            }
        }
    }

    fn send(&mut self, now: u64) {
        let want = (self.setup.size - self.sent).min(self.setup.mtu);
        if want == 0 {
            return;
        }
        let got = self.out.share(&mut self.all, want);
        if got == 0 {
            if let Some(limit) = self.out.stalled() {
                self.events.push((now, Event::Stalled(limit)));
            }
            if let Some(limit) = self.all.stalled() {
                self.events.push((now, Event::Blocked(limit)));
            }
            return;
        }
        let fin = self.sent + got == self.setup.size;
        let fresh = self.inbound.data(self.sent, got, fin).unwrap();
        assert_eq!(fresh, got);
        self.total.charge(fresh).unwrap();
        self.sent += got;
        self.events.push((now, Event::Sent(got)));
        assert!(self.out.used() <= self.out.limit());
        assert!(self.all.used() <= self.all.limit());
    }

    fn read(&mut self, now: u64) {
        let ready = self.total.highest() - self.total.consumed();
        let count = ready.min(self.setup.rate);
        self.inbound.consume(count);
        self.total.consume(count);
        let arrival = now + self.setup.delay;
        if let Some(limit) = self.inbound.grant() {
            self.events.push((now, Event::Stream(limit)));
            self.wire.push((arrival, true, limit));
        }
        if let Some(limit) = self.total.grant() {
            self.events.push((now, Event::Shared(limit)));
            self.wire.push((arrival, false, limit));
        }
    }

    fn run(mut self) -> (Vec<(u64, Event)>, u64) {
        let mut now = 0;
        while self.total.consumed() < self.setup.size {
            assert!(now < 100_000, "stuck");
            self.deliver(now);
            self.send(now);
            self.read(now);
            now += 1;
        }
        (self.events, now)
    }
}

fn small(stream: u64, shared: u64) -> Setup {
    Setup {
        stream,
        shared,
        size: 20,
        mtu: 4,
        rate: 2,
        delay: 2,
    }
}

#[test]
fn bound() {
    let (events, ticks) = Pair::new(small(8, 100)).run();
    let expected = vec![
        (0, Event::Sent(4)),
        (1, Event::Sent(4)),
        (1, Event::Stream(12)),
        (2, Event::Stalled(8)),
        (3, Event::Sent(4)),
        (3, Event::Stream(16)),
        (4, Event::Stalled(12)),
        (5, Event::Sent(4)),
        (5, Event::Stream(20)),
        (6, Event::Stalled(16)),
        (7, Event::Sent(4)),
        (7, Event::Stream(24)),
        (9, Event::Stream(28)),
    ];
    assert_eq!(events, expected);
    assert_eq!(ticks, 10);
}

#[test]
fn shared() {
    let (events, ticks) = Pair::new(small(100, 8)).run();
    let expected = vec![
        (0, Event::Sent(4)),
        (1, Event::Sent(4)),
        (1, Event::Shared(12)),
        (2, Event::Blocked(8)),
        (3, Event::Sent(4)),
        (3, Event::Shared(16)),
        (4, Event::Blocked(12)),
        (5, Event::Sent(4)),
        (5, Event::Shared(20)),
        (6, Event::Blocked(16)),
        (7, Event::Sent(4)),
        (7, Event::Shared(24)),
        (9, Event::Shared(28)),
    ];
    assert_eq!(events, expected);
    assert_eq!(ticks, 10);
}

#[test]
fn quick() {
    let (events, ticks) = Pair::new(small(1000, 1000)).run();
    let sent: Vec<u64> = events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::Sent(count) => Some(*count),
            _ => None,
        })
        .collect();
    assert_eq!(sent, vec![4; 5]);
    assert_eq!(events.last(), Some(&(4, Event::Sent(4))));
    assert_eq!(ticks, 10);
}

#[test]
fn varied() {
    for seed in 1..=60 {
        let mut dice = Dice::new(seed);
        let setup = Setup {
            stream: dice.within(1, 64),
            shared: dice.within(1, 64),
            size: dice.within(1, 500),
            mtu: dice.within(1, 16),
            rate: dice.within(1, 16),
            delay: dice.below(6),
        };
        let (size, mtu, rate) = (setup.size, setup.mtu, setup.rate);
        let (events, ticks) = Pair::new(setup).run();
        let sent: u64 = events
            .iter()
            .map(|(_, event)| match event {
                Event::Sent(count) => *count,
                _ => 0,
            })
            .sum();
        assert_eq!(sent, size, "seed {seed}");
        assert!(ticks >= size.div_ceil(rate), "seed {seed}");
        let over = events
            .iter()
            .any(|(_, event)| matches!(event, Event::Sent(count) if *count > mtu));
        assert!(!over, "seed {seed}");
    }
}
