use quic::{Ack, Error, Frame, Stream};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
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

    pub fn upto(&mut self, limit: usize) -> Vec<u8> {
        let count = self.below(limit);
        self.bytes(count)
    }

    pub fn span(&mut self, floor: usize, extra: usize) -> Vec<u8> {
        let count = floor + self.below(extra);
        self.bytes(count)
    }

    pub fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }
}

pub fn same(text: &str, frame: Frame) {
    let bytes = hex(text);
    let (found, used) = Frame::parse(&bytes).unwrap();
    assert_eq!(found, frame, "{text}");
    assert_eq!(used, bytes.len(), "{text}");
    assert_eq!(frame.write().unwrap(), bytes, "{text}");
}

pub fn fails(text: &str, error: Error) {
    assert_eq!(Frame::parse(&hex(text)), Err(error), "{text}");
}

pub fn stream(id: u64, offset: u64, data: &[u8], flags: (bool, bool)) -> Frame {
    Frame::Stream(Stream {
        id,
        offset,
        data: data.to_vec(),
        fin: flags.0,
        sized: flags.1,
    })
}

pub fn ack(largest: u64, delay: u64, first: u64, ranges: &[(u64, u64)]) -> Ack {
    Ack {
        largest,
        delay,
        first,
        ranges: ranges.to_vec(),
        ecn: None,
    }
}

pub const TOKEN: &str = "00112233445566778899aabbccddeeff";

pub fn token() -> [u8; 16] {
    hex(TOKEN).try_into().unwrap()
}
