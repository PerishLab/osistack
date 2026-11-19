use crate::support::*;
use quic::{Ack, Fired, Recovery, Space};
use std::collections::BTreeSet;

fn frame(seen: &BTreeSet<u64>) -> Ack {
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

enum Event {
    Send(u64),
    Ack(Ack),
}

struct Report {
    acked: Vec<u64>,
    lost: Vec<u64>,
    dropped: BTreeSet<u64>,
    recovery: Recovery,
}

fn plan(
    count: u64,
    jitter: u64,
    percent: u64,
    dice: &mut Dice,
) -> (BTreeSet<u64>, Vec<(u64, u64, Event)>) {
    let mut dropped = BTreeSet::new();
    let mut arrivals = Vec::new();
    for number in 0..count {
        let time = number * 10_000;
        if number + 6 < count && dice.below(100) < percent {
            dropped.insert(number);
        } else {
            arrivals.push((time + 50_000 + dice.below(jitter + 1), number));
        }
    }
    arrivals.sort();
    let mut events: Vec<(u64, u64, Event)> = Vec::new();
    for number in 0..count {
        events.push((number * 10_000, 0, Event::Send(number)));
    }
    let mut seen = BTreeSet::new();
    for (time, number) in arrivals {
        seen.insert(number);
        let back = time + 50_000 + dice.below(jitter + 1);
        events.push((back, 1, Event::Ack(frame(&seen))));
    }
    events.sort_by_key(|(time, rank, _)| (*time, *rank));
    (dropped, events)
}

fn tick(recovery: &mut Recovery, until: u64, lost: &mut Vec<u64>) {
    for _ in 0..5_000 {
        let Some(time) = recovery.deadline().filter(|time| *time <= until) else {
            return;
        };
        if let Fired::Lost(_, list) = recovery.expire(time) {
            lost.extend(numbers(&list));
        }
    }
    panic!("timer never settled");
}

fn run(count: u64, jitter: u64, percent: u64, seed: u64) -> Report {
    let mut dice = Dice::new(seed);
    let (dropped, events) = plan(count, jitter, percent, &mut dice);
    let mut recovery = client();
    let mut acked = Vec::new();
    let mut lost = Vec::new();
    for (time, _, event) in events {
        tick(&mut recovery, time, &mut lost);
        match event {
            Event::Send(number) => recovery.sent(Space::Data, packet(number, time)),
            Event::Ack(frame) => {
                let out = recovery.acked(time, Space::Data, &frame).unwrap();
                acked.extend(numbers(&out.acked));
                lost.extend(numbers(&out.lost));
            }
        }
    }
    tick(&mut recovery, u64::MAX, &mut lost);
    Report {
        acked,
        lost,
        dropped,
        recovery,
    }
}

#[test]
fn trace() {
    let mut recovery = client();
    for number in 0..6 {
        recovery.sent(Space::Data, packet(number, number * 10_000));
    }
    recovery.acked(100_000, Space::Data, &ack(0, 0)).unwrap();
    assert_eq!(recovery.deadline(), Some(375_000));
    recovery.acked(110_000, Space::Data, &ack(1, 1)).unwrap();
    assert_eq!(recovery.rtt().vary(), 37_500);
    assert_eq!(recovery.deadline(), Some(325_000));
    let holes = Ack {
        largest: 3,
        delay: 0,
        first: 0,
        ranges: vec![(0, 1)],
        ecn: None,
    };
    let out = recovery.acked(130_000, Space::Data, &holes).unwrap();
    assert_eq!(numbers(&out.acked), [3]);
    assert!(out.lost.is_empty());
    assert_eq!(recovery.rtt().vary(), 28_125);
    assert_eq!(recovery.deadline(), Some(132_500));
    let fired = recovery.expire(132_500);
    assert_eq!(fired, Fired::Lost(Space::Data, vec![packet(2, 20_000)]));
    assert_eq!(recovery.deadline(), Some(287_500));
    let holes = Ack {
        largest: 4,
        delay: 0,
        first: 1,
        ranges: vec![(0, 1)],
        ecn: None,
    };
    recovery.acked(140_000, Space::Data, &holes).unwrap();
    assert_eq!(recovery.rtt().vary(), 21_093);
    assert_eq!(recovery.deadline(), Some(259_372));
    let holes = Ack {
        largest: 5,
        delay: 0,
        first: 2,
        ranges: vec![(0, 1)],
        ecn: None,
    };
    recovery.acked(150_000, Space::Data, &holes).unwrap();
    assert_eq!(recovery.rtt().vary(), 15_819);
    assert_eq!(recovery.rtt().smooth(), 100_000);
    assert_eq!(recovery.deadline(), None);
}

#[test]
fn steady() {
    let report = run(200, 0, 12, 9);
    assert!(report.dropped.len() > 10);
    let lost: BTreeSet<u64> = report.lost.iter().copied().collect();
    assert_eq!(report.lost.len(), lost.len());
    assert_eq!(lost, report.dropped);
    assert_eq!(report.acked.len() + report.lost.len(), 200);
    assert_eq!(report.recovery.rtt().smooth(), 100_000);
    assert_eq!(report.recovery.rtt().floor(), 100_000);
    assert_eq!(report.recovery.rtt().latest(), 100_000);
    assert_eq!(report.recovery.deadline(), None);
    assert_eq!(report.recovery.pto(), 0);
}

#[test]
fn clean() {
    let report = run(50, 0, 0, 4);
    assert!(report.lost.is_empty());
    assert_eq!(report.acked, (0..50).collect::<Vec<u64>>());
}

fn partition(report: &Report, count: u64) {
    let acked: BTreeSet<u64> = report.acked.iter().copied().collect();
    let lost: BTreeSet<u64> = report.lost.iter().copied().collect();
    assert_eq!(acked.len(), report.acked.len());
    assert_eq!(lost.len(), report.lost.len());
    assert!(acked.is_disjoint(&lost));
    assert_eq!(acked.len() + lost.len(), count as usize);
    assert!(report.dropped.is_subset(&lost));
    assert!(acked.is_disjoint(&report.dropped));
    assert!(report.recovery.rtt().floor() >= 100_000);
    assert!(report.recovery.rtt().smooth() <= 160_000);
    assert_eq!(report.recovery.deadline(), None);
}

#[test]
fn jitter() {
    let mut spurious = 0;
    for seed in 0..60 {
        let report = run(120, 60_000, 8, seed);
        partition(&report, 120);
        spurious += report.lost.len() - report.dropped.len();
    }
    assert!(spurious > 0);
}

#[test]
fn gentle() {
    for seed in 0..30 {
        let report = run(120, 4_000, 5, seed);
        partition(&report, 120);
    }
}
