use crate::behaviour::Check;
use crate::quic::wire;
use crate::rules::rules;
use quic::{Ack, Arrival, Fired, Frame, Mark, Outcome, Received, Recovery, Reno, Sent, Space};
use std::collections::{BTreeMap, BTreeSet};

const DATA: Space = Space::Data;
const SIZE: u64 = 1200;
const DELAY: u64 = 25_000;
const TOTAL: u64 = 400;

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("newreno", newreno as Check)]
}

enum Event {
    Arrive(u64),
    Reply(Ack),
}

struct Step {
    before: u64,
    after: u64,
    bytes: u64,
    lost: usize,
    held: bool,
}

struct Sim {
    recovery: Recovery,
    control: Reno,
    peer: Received,
    queue: BTreeMap<(u64, u64), Event>,
    serial: u64,
    sent: u64,
    inside: u64,
    cap: u64,
    outage: (u64, u64),
    dropped: BTreeSet<u64>,
    arrived: BTreeSet<u64>,
    acked: BTreeSet<u64>,
    lost: BTreeSet<u64>,
    steps: Vec<Step>,
}

impl Sim {
    fn new(cap: u64, outage: (u64, u64)) -> Self {
        let mut recovery = Recovery::new(false, DELAY, 3);
        recovery.confirm(0);
        Self {
            recovery,
            control: Reno::new(SIZE, DELAY),
            peer: Received::new(DELAY, 3, 64),
            queue: BTreeMap::new(),
            serial: 0,
            sent: 0,
            inside: 0,
            cap,
            outage,
            dropped: BTreeSet::new(),
            arrived: BTreeSet::new(),
            acked: BTreeSet::new(),
            lost: BTreeSet::new(),
            steps: Vec::new(),
        }
    }

    fn later(&mut self, time: u64, event: Event) {
        self.serial += 1;
        self.queue.insert((time, self.serial), event);
    }

    fn send(&mut self, now: u64, probe: bool) {
        let number = self.sent;
        self.sent += 1;
        let packet = Sent {
            number,
            time: now,
            size: SIZE,
            eliciting: true,
            flight: true,
        };
        self.recovery.sent(DATA, packet.clone());
        self.control.sent(&packet);
        let cut = self.outage.0 <= now && now < self.outage.1;
        if self.inside >= self.cap || cut {
            self.dropped.insert(number);
        } else {
            self.inside += 1;
            self.later(now + DELAY, Event::Arrive(number));
        }
        if !probe {
            assert!(self.control.flight() <= self.control.window());
        }
    }

    fn settle(&mut self, now: u64, out: Outcome) {
        let before = self.control.window();
        let held = self.control.threshold().is_some();
        self.control.settle(now, &out, self.recovery.rtt());
        let bytes = out.acked.len() as u64 * SIZE;
        let step = Step {
            before,
            after: self.control.window(),
            bytes,
            lost: out.lost.len(),
            held,
        };
        self.steps.push(step);
        self.acked
            .extend(out.acked.iter().map(|packet| packet.number));
        self.lost
            .extend(out.lost.iter().map(|packet| packet.number));
    }

    fn reply(&mut self, now: u64) {
        let Some(ack) = self.peer.frame(DATA, now) else {
            return;
        };
        let Frame::Ack(ack) = wire(&[Frame::Ack(ack)]).remove(0) else {
            panic!("not an ack frame");
        };
        self.later(now + DELAY, Event::Reply(ack));
    }

    fn handle(&mut self, now: u64, event: Event) {
        match event {
            Event::Arrive(number) => {
                self.inside -= 1;
                self.arrived.insert(number);
                let arrival = Arrival {
                    number,
                    time: now,
                    eliciting: true,
                    mark: Mark::Plain,
                };
                self.peer.receive(DATA, arrival);
                self.reply(now);
            }
            Event::Reply(ack) => {
                let out = self.recovery.acked(now, DATA, &ack).unwrap();
                self.settle(now, out);
            }
        }
    }

    fn pump(&mut self, now: u64) {
        while self.sent < TOTAL && self.control.room() >= SIZE {
            self.send(now, false);
        }
    }

    fn fire(&mut self, now: u64) {
        match self.recovery.expire(now) {
            Fired::Lost(_, lost) => {
                let out = Outcome {
                    acked: Vec::new(),
                    lost,
                };
                self.settle(now, out);
            }
            Fired::Probe(_) => self.send(now, true),
            Fired::Anti(_) => {}
        }
    }

    fn step(&mut self) -> bool {
        let head = self.queue.keys().next().map(|key| key.0);
        let timer = self.recovery.deadline();
        let now = match (head, timer) {
            (None, None) => return false,
            (Some(time), None) => time,
            (None, Some(time)) => time,
            (Some(left), Some(right)) => left.min(right),
        };
        if timer == Some(now) && head != Some(now) {
            self.fire(now);
        } else if let Some((_, event)) = self.queue.pop_first() {
            self.handle(now, event);
        }
        self.pump(now);
        true
    }

    fn run(mut self) -> Self {
        self.pump(0);
        for _ in 0..100_000 {
            if !self.step() {
                return self;
            }
        }
        panic!("never settled");
    }

    fn accounted(&self) {
        assert!(self.lost.is_subset(&self.dropped));
        assert_eq!(self.lost, self.dropped);
        assert_eq!(self.acked, self.arrived);
        let all: BTreeSet<u64> = self.acked.union(&self.lost).copied().collect();
        assert_eq!(all, (0..self.sent).collect::<BTreeSet<u64>>());
        assert_eq!(self.control.flight(), 0);
    }
}

fn slow(steps: &[Step]) {
    let early: Vec<&Step> = steps.iter().filter(|s| !s.held && s.lost == 0).collect();
    assert!(early.len() > 10);
    for step in early {
        assert_eq!(step.after, step.before + step.bytes);
    }
}

fn halved(steps: &[Step]) -> usize {
    let at = steps.iter().position(|step| step.lost > 0).unwrap();
    let step = &steps[at];
    assert!(!step.held);
    assert_eq!(step.after, (step.before / 2).max(2 * SIZE));
    at
}

fn avoid(steps: &[Step]) {
    let later: Vec<&Step> = steps.iter().filter(|s| s.held && s.lost == 0).collect();
    assert!(later.len() > 10);
    let low = later.iter().map(|step| step.before).min().unwrap();
    let (mut total, mut bytes) = (0, 0);
    for step in later {
        assert!(step.after >= step.before);
        let growth = step.after - step.before;
        assert_eq!(growth % SIZE, 0);
        total += growth;
        bytes += step.bytes;
    }
    assert!(total > 0);
    assert!(total * low <= SIZE * (bytes + low));
}

fn newreno() {
    rules();
    let start = Reno::new(SIZE, DELAY);
    assert_eq!(start.window(), 10 * SIZE);
    assert_eq!(start.threshold(), None);
    let mut pinned = Reno::new(SIZE, DELAY);
    let packet = Sent {
        number: 0,
        time: 0,
        size: SIZE,
        eliciting: true,
        flight: true,
    };
    pinned.sent(&packet);
    pinned.limited(true);
    pinned.acked(std::slice::from_ref(&packet));
    assert_eq!((pinned.window(), pinned.flight()), (10 * SIZE, 0));
    let open = Sim::new(10_000, (0, 0)).run();
    open.accounted();
    assert!(open.dropped.is_empty());
    assert_eq!(open.control.threshold(), None);
    assert_eq!(open.control.window(), 10 * SIZE + TOTAL * SIZE);
    slow(&open.steps);
    let tight = Sim::new(24, (0, 0)).run();
    tight.accounted();
    assert!(!tight.dropped.is_empty());
    slow(&tight.steps[..halved(&tight.steps)]);
    avoid(&tight.steps);
    let top = tight.steps.iter().map(|step| step.after).max().unwrap();
    assert!(top < 4 * 24 * SIZE);
    assert!(tight.control.threshold().is_some());
    let outage = Sim::new(10_000, (100_000, 1_500_000)).run();
    outage.accounted();
    let hit = outage.steps.iter().find(|step| step.lost > 0).unwrap();
    assert_eq!(hit.after, 2 * SIZE + hit.bytes);
    assert!(hit.after < hit.before / 2);
    assert!(outage.control.window() > 2 * SIZE);
    assert!(!outage.dropped.is_empty());
}
