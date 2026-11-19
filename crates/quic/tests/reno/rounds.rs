use crate::support::*;
use quic::{Fired, Recovery, Reno, Space};
use std::collections::{BTreeMap, BTreeSet};

struct Link {
    recovery: Recovery,
    reno: Reno,
    number: u64,
    live: BTreeMap<u64, u64>,
    lost: Vec<u64>,
}

impl Link {
    fn new() -> Self {
        let mut recovery = Recovery::new(false, 25_000, 3);
        recovery.confirm(0);
        Self {
            recovery,
            reno: Reno::new(1200, 25_000),
            number: 0,
            live: BTreeMap::new(),
            lost: Vec::new(),
        }
    }

    fn send(&mut self, time: u64, count: u64) -> Vec<u64> {
        let mut numbers = Vec::new();
        for _ in 0..count {
            let each = packet(self.number, time);
            self.recovery.sent(Space::Data, each.clone());
            self.reno.sent(&each);
            self.live.insert(self.number, each.size);
            numbers.push(self.number);
            self.number += 1;
        }
        numbers
    }

    fn fill(&mut self, time: u64) -> Vec<u64> {
        let count = (self.reno.room() / 1200).min(150);
        let before = self.reno.flight();
        let numbers = self.send(time, count);
        assert!(self.reno.flight() <= before.max(self.reno.window()));
        self.reno.limited(self.reno.room() >= 1200);
        numbers
    }

    fn receive(&mut self, time: u64, seen: &BTreeSet<u64>) {
        let out = self
            .recovery
            .acked(time, Space::Data, &frame(seen))
            .unwrap();
        self.reno.settle(time, &out, self.recovery.rtt());
        for each in out.acked.iter().chain(&out.lost) {
            self.live.remove(&each.number);
        }
        self.lost.extend(out.lost.iter().map(|each| each.number));
    }

    fn round(&mut self, time: u64, dropped: &[usize]) -> u64 {
        let numbers = self.fill(time);
        let seen: BTreeSet<u64> = numbers
            .iter()
            .enumerate()
            .filter(|(index, _)| !dropped.contains(index))
            .map(|(_, number)| *number)
            .collect();
        if !seen.is_empty() {
            self.receive(time + 100_000, &seen);
        }
        self.reno.window()
    }
}

#[test]
fn doubling() {
    let mut link = Link::new();
    let mut windows = Vec::new();
    for round in 0..3 {
        windows.push(link.round(round * 101_000, &[]));
        assert_eq!(link.reno.flight(), 0);
    }
    assert_eq!(windows, [24_000, 48_000, 96_000]);
    assert_eq!(link.reno.threshold(), None);
    assert!(link.lost.is_empty());
}

#[test]
fn halving() {
    let mut link = Link::new();
    for round in 0..3 {
        link.round(round * 101_000, &[]);
    }
    assert_eq!(link.round(303_000, &[0]), 48_000);
    assert_eq!(link.lost, [70]);
    assert_eq!(link.reno.threshold(), Some(48_000));
    assert_eq!(link.reno.start(), Some(403_000));
    assert_eq!(link.reno.flight(), 0);
    let mut windows = Vec::new();
    for round in 4..7 {
        windows.push(link.round(round * 101_000, &[]));
    }
    assert_eq!(windows, [49_200, 50_400, 51_600]);
    assert_eq!(link.lost, [70]);
}

#[test]
fn blackhole() {
    let mut link = Link::new();
    link.round(0, &[]);
    link.round(101_000, &[]);
    assert_eq!(link.reno.window(), 48_000);
    let first = link.fill(202_000);
    assert_eq!(first.len(), 40);
    assert_eq!(link.reno.room(), 0);
    for time in [502_000, 802_000, 1_102_000, 1_402_000] {
        assert_eq!(link.send(time, 1).len(), 1);
    }
    assert_eq!(link.reno.flight(), 52_800);
    assert_eq!(link.reno.window(), 48_000);
    link.send(1_702_000, 1);
    let seen = BTreeSet::from([74]);
    link.receive(1_802_000, &seen);
    assert_eq!(link.lost, (30..74).collect::<Vec<u64>>());
    assert_eq!(link.reno.threshold(), Some(24_000));
    assert_eq!(link.reno.start(), None);
    assert_eq!(link.reno.window(), 3_600);
    assert_eq!(link.reno.flight(), 0);
    assert!(link.live.is_empty());
}

#[test]
fn stalled() {
    let mut link = Link::new();
    link.round(0, &[]);
    let numbers = link.fill(101_000);
    assert_eq!(numbers.len(), 20);
    assert_eq!(link.reno.room(), 0);
    link.send(300_000, 2);
    assert_eq!(link.reno.flight(), 26_400);
    assert_eq!(link.reno.room(), 0);
    let expired = link
        .recovery
        .deadline()
        .map(|time| link.recovery.expire(time));
    assert!(matches!(expired, Some(Fired::Probe(Space::Data))));
}

#[test]
fn sweep() {
    for seed in 0..40 {
        let mut dice = Dice::new(seed);
        let percent = dice.below(13);
        let mut link = Link::new();
        for round in 0..60 {
            let before = link.reno.window();
            let drops: Vec<usize> = (0..400).filter(|_| dice.below(100) < percent).collect();
            link.round(round * 101_000, &drops);
            assert!(link.reno.window() >= 2_400);
            let held: u64 = link.live.values().sum();
            assert_eq!(link.reno.flight(), held);
            if link.lost.is_empty() {
                assert!(link.reno.window() >= before);
            }
        }
        assert!(percent == 0 || !link.lost.is_empty());
    }
}
