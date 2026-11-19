use crate::support::*;
use quic::{Choked, Direction, Fault, Lanes, Role};
use std::collections::BTreeSet;

struct Model {
    bit: u64,
    opened: [u64; 2],
    cap: [u64; 2],
    seen: [BTreeSet<u64>; 2],
    closed: [u64; 2],
    window: [u64; 2],
    admitted: [u64; 2],
}

fn kind(slot: usize) -> Direction {
    [Direction::Bidi, Direction::Uni][slot]
}

impl Model {
    fn open(&mut self, slot: usize) -> Result<u64, Choked> {
        if self.opened[slot] == self.cap[slot] {
            return Err(Choked(self.cap[slot]));
        }
        self.opened[slot] += 1;
        Ok((self.opened[slot] - 1) * 4 + slot as u64 * 2 + self.bit)
    }

    fn admit(&mut self, id: u64) -> Result<Vec<u64>, Fault> {
        let slot = ((id >> 1) & 1) as usize;
        let index = id >> 2;
        if id & 1 == self.bit {
            let known = slot == 0 && index < self.opened[0];
            return if known { Ok(vec![]) } else { Err(Fault::State) };
        }
        if index + 1 > self.admitted[slot] {
            return Err(Fault::Limit);
        }
        let fresh: Vec<u64> = (0..=index)
            .filter(|n| !self.seen[slot].contains(n))
            .collect();
        self.seen[slot].extend(fresh.iter().copied());
        Ok(fresh
            .iter()
            .map(|n| n * 4 + slot as u64 * 2 + (id & 1))
            .collect())
    }

    fn close(&mut self, id: u64) {
        let slot = ((id >> 1) & 1) as usize;
        if id & 1 != self.bit {
            self.closed[slot] = (self.closed[slot] + 1).min(self.seen[slot].len() as u64);
        }
    }

    fn grant(&mut self, slot: usize) -> Option<u64> {
        let target = self.closed[slot] + self.window[slot];
        let enough = target - self.admitted[slot].min(target) >= self.window[slot] / 2;
        if target > self.admitted[slot] && enough {
            self.admitted[slot] = target;
            return Some(target);
        }
        None
    }

    fn raise(&mut self, slot: usize, limit: u64) -> bool {
        let more = limit > self.cap[slot];
        if more {
            self.cap[slot] = limit;
        }
        more
    }
}

fn step(dice: &mut Dice, lanes: &mut Lanes, model: &mut Model) {
    let slot = dice.below(2) as usize;
    match dice.below(5) {
        0 => assert_eq!(lanes.open(kind(slot)), model.open(slot)),
        1 => {
            let id = dice.below(80);
            assert_eq!(lanes.admit(id), model.admit(id), "admit {id}");
        }
        2 => {
            let id = dice.below(80);
            lanes.close(id);
            model.close(id);
        }
        3 => assert_eq!(lanes.grant(kind(slot)), model.grant(slot)),
        _ => {
            let limit = dice.below(12);
            assert_eq!(lanes.raise(kind(slot), limit), model.raise(slot, limit));
        }
    }
}

#[test]
fn random() {
    for seed in 1..=80 {
        for role in [Role::Client, Role::Server] {
            let mut dice = Dice::new(seed);
            let open = [dice.below(8), dice.below(8)];
            let admit = [dice.within(1, 10), dice.within(1, 10)];
            let mut lanes = Lanes::new(role, open, admit);
            let mut model = Model {
                bit: if role == Role::Client { 0 } else { 1 },
                opened: [0; 2],
                cap: open,
                seen: [BTreeSet::new(), BTreeSet::new()],
                closed: [0; 2],
                window: admit,
                admitted: admit,
            };
            for _ in 0..120 {
                step(&mut dice, &mut lanes, &mut model);
            }
        }
    }
}
