use h2::{Flow, Misuse};
use std::collections::BTreeMap;

const TOP: i64 = 0x7fff_ffff;

struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % sides
    }
}

#[derive(Default)]
struct Ledger {
    initial: i64,
    credits: i64,
    spent: i64,
}

impl Ledger {
    fn window(&self) -> i64 {
        self.initial + self.credits - self.spent
    }

    fn credit(&mut self, amount: i64) -> bool {
        let fits = self.window() + amount <= TOP;
        if fits {
            self.credits += amount;
        }
        fits
    }
}

struct World {
    flow: Flow,
    connection: Ledger,
    streams: BTreeMap<u32, Ledger>,
    initial: i64,
}

impl World {
    fn new() -> Self {
        let connection = Ledger {
            initial: 65_535,
            ..Ledger::default()
        };
        Self {
            flow: Flow::new(),
            connection,
            streams: BTreeMap::new(),
            initial: 65_535,
        }
    }

    fn room(&self, stream: u32) -> i64 {
        let own = self.streams.get(&stream).map_or(0, Ledger::window);
        own.min(self.connection.window()).max(0)
    }

    fn open(&mut self, stream: u32) {
        self.flow.open(stream);
        let initial = self.initial;
        let fresh = Ledger {
            initial,
            ..Ledger::default()
        };
        self.streams.entry(stream).or_insert(fresh);
    }

    fn close(&mut self, stream: u32) {
        self.flow.close(stream);
        self.streams.remove(&stream);
    }

    fn send(&mut self, stream: u32, length: u32) {
        let tracked = self.streams.contains_key(&stream);
        let want = tracked && i64::from(length) <= self.room(stream);
        let got = self.flow.send(stream, length);
        assert_eq!(got.is_ok(), want);
        if !tracked {
            assert_eq!(got, Err(Misuse::Closed));
        }
        if want {
            let spent = i64::from(length);
            self.connection.spent += spent;
            self.streams.get_mut(&stream).unwrap().spent += spent;
        }
    }

    fn credit(&mut self, target: u32, amount: u32) {
        let ledger = match target {
            0 => Some(&mut self.connection),
            _ => self.streams.get_mut(&target),
        };
        let want = ledger.is_none_or(|ledger| ledger.credit(i64::from(amount)));
        assert_eq!(self.flow.credit(target, amount).is_ok(), want);
    }

    fn remote(&mut self, size: i64) {
        let delta = size - self.initial;
        self.initial = size;
        for ledger in self.streams.values_mut() {
            ledger.initial += delta;
        }
        self.flow.remote(size as u32).unwrap();
    }

    fn check(&self) {
        for (id, ledger) in &self.streams {
            assert_eq!(self.flow.outgoing(*id), Some(ledger.window()));
            assert_eq!(i64::from(self.flow.room(*id)), self.room(*id));
        }
        assert_eq!(self.flow.outgoing(0), Some(self.connection.window()));
    }

    fn step(&mut self, dice: &mut Dice) {
        let stream = [1u32, 3, 5][dice.roll(3) as usize];
        match dice.roll(8) {
            0 => self.open(stream),
            1 => self.close(stream),
            2 | 3 => self.send(stream, dice.roll(30_000) as u32),
            4 => {
                let target = if dice.roll(3) == 0 { 0 } else { stream };
                self.credit(target, dice.roll(20_000) as u32 + 1);
            }
            5 => self.remote(dice.roll(120_000) as i64),
            _ => {}
        }
        self.check();
    }
}

#[test]
fn ledger() {
    for seed in 1..=40u64 {
        let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut world = World::new();
        for _ in 0..1500 {
            world.step(&mut dice);
        }
    }
}
