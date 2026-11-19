use crate::support::*;
use h3::{Decoder, Dynamic, Encoder, Feedback, Field, Instruction, Name};

struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % sides
    }
}

struct World {
    mirror: Dynamic,
    decoder: Decoder,
    encoder: Encoder,
    dice: Dice,
}

impl World {
    fn new(seed: u64, huffman: bool) -> Self {
        let mut decoder = Decoder::new(160).blocked(4);
        decoder.apply(&capacity(160)).unwrap();
        Self {
            mirror: table(160, &[]),
            decoder,
            encoder: Encoder::new(huffman),
            dice: Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        }
    }

    fn grow(&mut self) -> Vec<u8> {
        let name = format!("n{}", self.dice.roll(4));
        let value = "v".repeat(self.dice.roll(12) as usize);
        let entry = Instruction::Insert {
            name: Name::Literal(name.as_bytes().to_vec()),
            value: value.as_bytes().to_vec(),
        };
        self.mirror.insert(field(&name, &value)).unwrap();
        entry.encode(None).unwrap()
    }

    fn fields(&mut self) -> Vec<Field> {
        let live = self.mirror.entries();
        let count = 1 + self.dice.roll(4) as usize;
        let mut list = Vec::new();
        for _ in 0..count {
            let pick = self.dice.roll(5);
            let source = &live[self.dice.roll(live.len() as u64) as usize];
            let mut item = source.clone();
            match pick {
                0 => item.value.push(b'!'),
                1 => item.sensitive = true,
                2 => item = field(":method", "GET"),
                3 => item = field("x-fresh", "1"),
                _ => {}
            }
            list.push(item);
        }
        list
    }

    fn round(&mut self) {
        let fields = self.fields();
        let base = self.dice.roll(self.mirror.inserted() + 1);
        let bytes = self.encoder.reference(&self.mirror, base, &fields).unwrap();
        let decoded = self.decoder.section(4, &bytes).unwrap().unwrap();
        assert_eq!(decoded.fields, fields);
        let used = bytes[0] != 0;
        assert_eq!(decoded.feedback.is_some(), used);
        if let Some(feedback) = decoded.feedback {
            assert_eq!(feedback, Feedback::Acknowledge(4));
        }
    }
}

#[test]
fn rounds() {
    for seed in 1..=30u64 {
        let mut world = World::new(seed, seed % 2 == 0);
        for _ in 0..30 {
            let bytes = world.grow();
            world.decoder.apply(&bytes).unwrap();
            world.round();
        }
        assert_eq!(world.decoder.table().entries(), world.mirror.entries());
        assert!(world.mirror.dropped() > 0);
    }
}

#[test]
fn blocked() {
    for seed in 1..=30u64 {
        let mut world = World::new(seed, false);
        for _ in 0..6 {
            let bytes = world.grow();
            world.decoder.apply(&bytes).unwrap();
        }
        let pending: Vec<Vec<u8>> = (0..4).map(|_| world.grow()).collect();
        let fields = world.fields();
        let base = world.dice.roll(world.mirror.inserted() + 1);
        let bytes = world
            .encoder
            .reference(&world.mirror, base, &fields)
            .unwrap();
        let mut found = world.decoder.section(4, &bytes).unwrap();
        let stream = pending.concat();
        let cut = stream.len() / 2;
        let mut at = 0;
        for end in [cut, stream.len()] {
            at += world.decoder.apply(&stream[at..end]).unwrap();
            if let Some(item) = world.decoder.ready().unwrap().pop() {
                found = Some(item);
            }
        }
        assert_eq!(at, stream.len());
        assert_eq!(found.unwrap().fields, fields);
        assert_eq!(world.decoder.waiting(), 0);
    }
}
