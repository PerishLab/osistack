use crate::support::*;
use quic::{Mark, Received, Recovery, Seen, Space};
use std::collections::BTreeSet;

const DATA: Space = Space::Data;
const DELAY: u64 = 25_000;

fn fresh() -> Received {
    Received::new(DELAY, 3, 64)
}

#[test]
fn early() {
    let mut got = fresh();
    for space in [Space::Initial, Space::Handshake] {
        got.receive(space, arrival(0, 700));
        assert_eq!(got.deadline(space), Some(700));
    }
    assert_eq!(got.deadline(DATA), None);
    assert_eq!(got.next(), Some(700));
    got.receive(DATA, arrival(0, 900));
    assert_eq!(got.deadline(DATA), Some(900 + DELAY));
    assert_eq!(got.next(), Some(700));
    got.frame(Space::Initial, 700).unwrap();
    got.frame(Space::Handshake, 700).unwrap();
    assert_eq!(got.next(), Some(900 + DELAY));
}

#[test]
fn second() {
    let mut got = fresh();
    got.receive(DATA, arrival(0, 1_000));
    got.receive(DATA, arrival(1, 3_000));
    assert_eq!(got.deadline(DATA), Some(3_000));
    got.frame(DATA, 3_000).unwrap();
    got.receive(DATA, arrival(2, 4_000));
    assert_eq!(got.deadline(DATA), Some(29_000));
    got.receive(DATA, arrival(3, 5_000));
    assert_eq!(got.deadline(DATA), Some(5_000));
}

#[test]
fn kept() {
    let mut got = fresh();
    got.receive(DATA, arrival(0, 1_000));
    got.receive(DATA, arrival(1, 90_000));
    assert_eq!(got.deadline(DATA), Some(26_000));
}

#[test]
fn quiet() {
    let mut got = fresh();
    got.receive(DATA, silent(0, 1_000));
    got.receive(DATA, silent(1, 1_000));
    got.receive(DATA, silent(2, 1_000));
    assert_eq!(got.deadline(DATA), None);
    assert_eq!(got.next(), None);
    got.receive(DATA, arrival(3, 1_000));
    assert_eq!(got.deadline(DATA), Some(26_000));
    let frame = got.frame(DATA, 2_000).unwrap();
    assert_eq!((frame.largest, frame.first), (3, 3));
    assert_eq!(got.deadline(DATA), None);
    assert_eq!(got.frame(DATA, 2_000), None);
}

#[test]
fn gapped() {
    let mut got = fresh();
    got.receive(DATA, arrival(0, 0));
    got.frame(DATA, 0).unwrap();
    got.receive(DATA, arrival(1, 10));
    assert_eq!(got.deadline(DATA), Some(10 + DELAY));
    got.frame(DATA, 10).unwrap();
    got.receive(DATA, arrival(3, 20));
    assert_eq!(got.deadline(DATA), Some(20));
}

#[test]
fn shuffled() {
    let mut got = fresh();
    got.receive(DATA, arrival(5, 0));
    got.frame(DATA, 0).unwrap();
    got.receive(DATA, arrival(4, 10));
    assert_eq!(got.deadline(DATA), Some(10));
    got.frame(DATA, 10).unwrap();
    got.receive(DATA, arrival(6, 20));
    assert_eq!(got.deadline(DATA), Some(20 + DELAY));
    got.frame(DATA, 20).unwrap();
    got.receive(DATA, silent(1, 30));
    assert_eq!(got.deadline(DATA), None);
}

#[test]
fn lowered() {
    let mut got = fresh();
    got.receive(DATA, arrival(10, 0));
    got.frame(DATA, 0).unwrap();
    got.receive(DATA, arrival(3, 10));
    assert_eq!(got.deadline(DATA), Some(10));
    got.frame(DATA, 10).unwrap();
    got.receive(DATA, arrival(11, 20));
    assert_eq!(got.deadline(DATA), Some(20 + DELAY));
}

#[test]
fn filled() {
    let mut got = fresh();
    got.receive(DATA, arrival(0, 0));
    got.frame(DATA, 0).unwrap();
    got.receive(DATA, silent(1, 5));
    got.receive(DATA, arrival(2, 10));
    assert_eq!(got.deadline(DATA), Some(10 + DELAY));
}

#[test]
fn trimmed() {
    let mut got = fresh();
    got.receive(DATA, arrival(5, 0));
    got.receive(DATA, silent(6, 0));
    got.carried(DATA, 1, 5);
    got.confirmed(DATA, 1);
    assert_eq!(got.ranges(DATA), [(6, 6)]);
    got.frame(DATA, 0).unwrap();
    got.receive(DATA, arrival(7, 40));
    assert_eq!(got.deadline(DATA), Some(40 + DELAY));
}

#[test]
fn flagged() {
    let mut got = fresh();
    got.receive(DATA, marked(0, 100, Mark::Ect0));
    assert_eq!(got.deadline(DATA), Some(100 + DELAY));
    got.frame(DATA, 100).unwrap();
    got.receive(DATA, marked(1, 200, Mark::Ce));
    assert_eq!(got.deadline(DATA), Some(200));
    got.frame(DATA, 200).unwrap();
    let quiet = quic::Arrival {
        eliciting: false,
        ..marked(2, 300, Mark::Ce)
    };
    got.receive(DATA, quiet);
    assert_eq!(got.deadline(DATA), None);
}

#[test]
fn shape() {
    let mut got = fresh();
    for number in [0, 1, 2, 5, 6, 9] {
        got.receive(DATA, silent(number, 0));
    }
    let frame = got.frame(DATA, 0).unwrap();
    assert_eq!(frame.largest, 9);
    assert_eq!(frame.first, 0);
    assert_eq!(frame.ranges, [(1, 1), (1, 2)]);
    assert_eq!(trip(&frame), frame);
    got.receive(DATA, silent(10, 0));
    got.receive(DATA, silent(4, 0));
    let frame = got.frame(DATA, 0).unwrap();
    assert_eq!((frame.largest, frame.first), (10, 1));
    assert_eq!(frame.ranges, [(1, 2), (0, 2)]);
    assert_eq!(trip(&frame), frame);
    let mut got = fresh();
    got.receive(DATA, silent(0, 0));
    got.receive(DATA, silent(2, 0));
    let frame = got.frame(DATA, 0).unwrap();
    assert_eq!(frame.ranges, [(0, 0)]);
    assert_eq!(trip(&frame), frame);
}

#[test]
fn stamped() {
    let mut got = fresh();
    got.receive(DATA, arrival(5, 100));
    got.receive(DATA, arrival(3, 500));
    assert_eq!(got.frame(DATA, 600).unwrap().delay, 62);
    got.receive(DATA, arrival(6, 700));
    assert_eq!(got.frame(DATA, 700).unwrap().delay, 0);
    got.receive(DATA, arrival(7, 800));
    assert_eq!(got.frame(DATA, 807).unwrap().delay, 0);
    got.receive(DATA, arrival(8, 900));
    assert_eq!(got.frame(DATA, 908).unwrap().delay, 1);
    got.receive(DATA, arrival(9, 1_000));
    assert_eq!(got.frame(DATA, 800).unwrap().delay, 0);
}

#[test]
fn scaled() {
    let mut got = Received::new(DELAY, 25, 64);
    got.receive(DATA, arrival(0, 0));
    assert_eq!(got.frame(DATA, 3 << 20).unwrap().delay, 3);
    let mut got = Received::new(DELAY, 0, 64);
    got.receive(DATA, arrival(0, 0));
    assert_eq!(got.frame(DATA, 77).unwrap().delay, 77);
}

fn shuffle(dice: &mut Dice, order: &mut [u64]) {
    for at in (1..order.len()).rev() {
        order.swap(at, dice.below(at as u64 + 1) as usize);
    }
}

fn ranges(seen: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &number in seen {
        match runs.last_mut() {
            Some((_, high)) if *high + 1 == number => *high = number,
            _ => runs.push((number, number)),
        }
    }
    runs
}

#[test]
fn model() {
    for seed in 0..32 {
        let mut dice = Dice::new(seed);
        let mut order: Vec<u64> = (0..60).collect();
        shuffle(&mut dice, &mut order);
        let mut got = fresh();
        let mut seen = BTreeSet::new();
        for (step, number) in order.into_iter().enumerate() {
            let mut packet = arrival(number, step as u64 * 100);
            packet.eliciting = dice.below(3) != 0;
            assert_eq!(got.receive(DATA, packet), Seen::Fresh);
            seen.insert(number);
            assert_eq!(got.receive(DATA, packet), Seen::Repeat);
            assert_eq!(got.ranges(DATA), ranges(&seen), "{seed} {step}");
            let frame = got.frame(DATA, step as u64 * 100).unwrap();
            assert_eq!(trip(&frame), frame);
            assert_eq!(frame.largest, *seen.iter().next_back().unwrap());
        }
    }
}

struct Trial {
    sent: BTreeSet<u64>,
    acked: BTreeSet<u64>,
    lost: BTreeSet<u64>,
}

fn run(seed: u64, mixed: bool) -> Trial {
    let mut dice = Dice::new(seed);
    let mut recovery = Recovery::new(false, DELAY, 3);
    recovery.confirm(0);
    let mut sent: Vec<u64> = (0..50).collect();
    for number in 0..50 {
        recovery.sent(DATA, packet(number, number * 10));
    }
    sent.retain(|_| dice.below(4) != 0);
    if mixed {
        shuffle(&mut dice, &mut sent);
    }
    let mut got = fresh();
    let mut trial = Trial {
        sent: sent.iter().copied().collect(),
        acked: BTreeSet::new(),
        lost: BTreeSet::new(),
    };
    let mut now = 10_000;
    let mut frames = Vec::new();
    for number in sent {
        now += 1_000 + dice.below(40_000);
        while let Some(due) = got.next().filter(|due| *due <= now) {
            frames.push((due, got.frame(DATA, due).unwrap()));
        }
        got.receive(DATA, arrival(number, now));
    }
    frames.extend(got.frame(DATA, now).map(|frame| (now, frame)));
    for (at, frame) in frames {
        let out = recovery.acked(at + 10_000, DATA, &trip(&frame)).unwrap();
        trial.acked.extend(out.acked.iter().map(|sent| sent.number));
        trial.lost.extend(out.lost.iter().map(|sent| sent.number));
    }
    trial
}

#[test]
fn closed() {
    for seed in 0..32 {
        let trial = run(seed, false);
        assert_eq!(trial.sent, trial.acked, "{seed}");
        assert!(trial.lost.is_disjoint(&trial.sent), "{seed}");
    }
}

#[test]
fn late() {
    for seed in 0..32 {
        let trial = run(seed, true);
        assert!(trial.acked.is_subset(&trial.sent), "{seed}");
        let known: BTreeSet<u64> = trial.acked.union(&trial.lost).copied().collect();
        assert!(trial.sent.is_subset(&known), "{seed}");
        assert!(trial.acked.is_disjoint(&trial.lost), "{seed}");
    }
}
