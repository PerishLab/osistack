use tls::{Extension, Kind, Message};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn unwrap(text: &str, kind: Kind) -> Vec<u8> {
    let wire = hex(text);
    let (message, used) = Message::parse(&wire, 1 << 16).unwrap().unwrap();
    assert_eq!((message.kind, used), (kind, wire.len()));
    assert_eq!(message.write().unwrap(), wire);
    message.body
}

pub fn kinds(extensions: &[Extension]) -> Vec<u16> {
    extensions.iter().map(|extension| extension.kind).collect()
}

pub fn extension(kind: u16, data: &[u8]) -> Extension {
    Extension {
        kind,
        data: data.to_vec(),
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

    pub fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    pub fn span(&mut self, floor: usize, extra: usize) -> Vec<u8> {
        let count = floor + self.below(extra);
        self.bytes(count)
    }

    pub fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }
}
