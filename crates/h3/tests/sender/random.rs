use crate::support::*;
use h3::{Decoded, Decoder, Field, Sender};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const NAMES: [&str; 6] = [
    "x-a",
    "x-b",
    ":authority",
    "content-type",
    ":method",
    "x-long-header-name",
];
const VALUES: [&str; 5] = [
    "1",
    "2",
    "GET",
    "text/html",
    "a-rather-long-value-for-eviction",
];

struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % sides as u64) as usize
    }
}

struct Wires {
    wire: VecDeque<Vec<u8>>,
    back: VecDeque<Vec<u8>>,
    held: Vec<(u64, Vec<u8>)>,
}

struct Book {
    expect: BTreeMap<u64, Vec<Field>>,
    waiting: BTreeSet<u64>,
    done: BTreeSet<u64>,
    next: u64,
}

struct World {
    sender: Sender,
    decoder: Decoder,
    dice: Dice,
    limit: usize,
    wires: Wires,
    book: Book,
}

fn pairs(fields: &[Field]) -> Vec<(Vec<u8>, Vec<u8>)> {
    fields
        .iter()
        .map(|line| (line.name.clone(), line.value.clone()))
        .collect()
}

impl World {
    fn new(maximum: usize, limit: usize, huffman: bool, seed: u64) -> Self {
        let wires = Wires {
            wire: VecDeque::new(),
            back: VecDeque::new(),
            held: Vec::new(),
        };
        let book = Book {
            expect: BTreeMap::new(),
            waiting: BTreeSet::new(),
            done: BTreeSet::new(),
            next: 0,
        };
        Self {
            sender: Sender::new(maximum, limit, huffman),
            decoder: Decoder::new(maximum).blocked(limit),
            dice: Dice(seed * 2654435761 + 1),
            limit,
            wires,
            book,
        }
    }

    fn capacity(&mut self, value: usize) {
        if let Ok(bytes) = self.sender.capacity(value) {
            self.wires.wire.push_back(bytes);
        }
    }

    fn fields(&mut self) -> Vec<Field> {
        let count = 1 + self.dice.roll(5);
        let mut fields = Vec::new();
        for _ in 0..count {
            let value = VALUES[self.dice.roll(VALUES.len())];
            if self.dice.roll(8) == 0 {
                fields.push(secret("authorization", value));
            } else {
                fields.push(field(NAMES[self.dice.roll(NAMES.len())], value));
            }
        }
        fields
    }

    fn encode(&mut self) {
        let stream = self.book.next;
        self.book.next += 4;
        let fields = self.fields();
        let encoded = self.sender.encode(stream, &fields).unwrap();
        if !encoded.instructions.is_empty() {
            self.wires.wire.push_back(encoded.instructions);
        }
        self.wires.held.push((stream, encoded.block));
        self.book.expect.insert(stream, fields);
    }

    fn check(&mut self, decoded: Decoded) {
        let expected = self.book.expect.get(&decoded.stream).unwrap();
        assert_eq!(
            pairs(&decoded.fields),
            pairs(expected),
            "{}",
            decoded.stream
        );
        self.book.waiting.remove(&decoded.stream);
        self.book.done.insert(decoded.stream);
        if let Some(feedback) = decoded.feedback {
            self.wires.back.push_back(feedback.encode().unwrap());
        }
    }

    fn apply(&mut self) {
        let Some(chunk) = self.wires.wire.pop_front() else {
            return;
        };
        assert_eq!(self.decoder.apply(&chunk).unwrap(), chunk.len());
        for decoded in self.decoder.ready().unwrap() {
            self.check(decoded);
        }
        if self.dice.roll(3) == 0 {
            self.nudge();
        }
    }

    fn nudge(&mut self) {
        if let Some(feedback) = self.decoder.increment() {
            self.wires.back.push_back(feedback.encode().unwrap());
        }
    }

    fn deliver(&mut self) {
        if self.wires.held.is_empty() {
            return;
        }
        let at = self.dice.roll(self.wires.held.len());
        let (stream, block) = self.wires.held.remove(at);
        match self.decoder.section(stream, &block).unwrap() {
            Some(decoded) => self.check(decoded),
            None => {
                self.book.waiting.insert(stream);
            }
        }
    }

    fn feed(&mut self) {
        let Some(bytes) = self.wires.back.pop_front() else {
            return;
        };
        assert_eq!(self.sender.receive(&bytes).unwrap(), bytes.len());
    }

    fn cancel(&mut self) {
        let count = self.book.waiting.len();
        if count == 0 {
            return;
        }
        let stream = *self.book.waiting.iter().nth(self.dice.roll(count)).unwrap();
        self.book.waiting.remove(&stream);
        self.book.expect.remove(&stream);
        let feedback = self.decoder.cancel(stream);
        self.wires.back.push_back(feedback.encode().unwrap());
    }

    fn step(&mut self, maximum: usize) {
        match self.dice.roll(12) {
            0..=3 => self.encode(),
            4..=5 => self.apply(),
            6..=7 => self.deliver(),
            8 => self.feed(),
            9 => self.cancel(),
            10 => {
                let value = [0, 100, maximum][self.dice.roll(3)];
                self.capacity(value.min(maximum));
            }
            _ => self.feed(),
        }
        assert!(self.sender.tracker().blocked() <= self.limit);
        assert!(self.decoder.waiting() <= self.limit);
    }

    fn drain(&mut self) {
        while !self.wires.wire.is_empty() {
            self.apply();
        }
        while !self.wires.held.is_empty() {
            self.deliver();
        }
        for decoded in self.decoder.ready().unwrap() {
            self.check(decoded);
        }
        self.nudge();
        while !self.wires.back.is_empty() {
            self.feed();
        }
        assert!(self.book.waiting.is_empty());
        let expected: BTreeSet<u64> = self.book.expect.keys().copied().collect();
        assert_eq!(expected, self.book.done);
        let mine = self.sender.tracker().table().entries();
        assert_eq!(mine, self.decoder.table().entries());
    }
}

struct Config {
    maximum: usize,
    capacity: usize,
    limit: usize,
    huffman: bool,
}

fn configs() -> Vec<Config> {
    let sizes = [(0, 0), (64, 64), (220, 220), (1000, 1000), (1000, 220)];
    let mut found = Vec::new();
    for (maximum, capacity) in sizes {
        for limit in [0, 1, 3] {
            for huffman in [false, true] {
                found.push(Config {
                    maximum,
                    capacity,
                    limit,
                    huffman,
                });
            }
        }
    }
    found
}

fn run(config: &Config, seed: u64) {
    let mut world = World::new(config.maximum, config.limit, config.huffman, seed);
    world.capacity(config.capacity);
    for _ in 0..200 {
        world.step(config.maximum);
    }
    world.drain();
}

#[test]
fn delivery() {
    for config in configs() {
        for seed in 1..=40 {
            run(&config, seed);
        }
    }
}

#[test]
fn sequence() {
    let mut sender = Sender::new(1000, 4, false);
    let mut decoder = Decoder::new(1000).blocked(4);
    decoder.apply(&sender.capacity(1000).unwrap()).unwrap();
    let first = sender.encode(4, &[field("ka", "1")]).unwrap();
    let second = sender
        .encode(4, &[field("kb", "1"), field("ka", "1")])
        .unwrap();
    assert_eq!(sender.tracker().outstanding(4), 2);
    decoder.apply(&first.instructions).unwrap();
    decoder.apply(&second.instructions).unwrap();
    let one = decoder.section(4, &first.block).unwrap().unwrap();
    let two = decoder.section(4, &second.block).unwrap().unwrap();
    assert_eq!(pairs(&one.fields), pairs(&[field("ka", "1")]));
    assert_eq!(
        pairs(&two.fields),
        pairs(&[field("kb", "1"), field("ka", "1")])
    );
    sender.receive(&ack(4)).unwrap();
    assert_eq!(
        (sender.tracker().known(), sender.tracker().outstanding(4)),
        (1, 1)
    );
    sender.receive(&ack(4)).unwrap();
    assert_eq!(
        (sender.tracker().known(), sender.tracker().outstanding(4)),
        (2, 0)
    );
}
