use quic::{Piece, Sending};

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

    pub fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }

    pub fn within(&mut self, low: u64, high: u64) -> u64 {
        low + self.below(high - low + 1)
    }
}

pub fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut dice = Dice::new(seed);
    (0..len).map(|_| dice.next() as u8).collect()
}

pub fn pull(sending: &mut Sending, max: usize) -> Vec<Piece> {
    let mut found = Vec::new();
    while let Some(piece) = sending.next(max) {
        found.push(piece);
        assert!(found.len() < 10_000);
    }
    found
}

pub fn piece(offset: u64, data: &[u8], fin: bool) -> Piece {
    Piece {
        offset,
        data: data.to_vec(),
        fin,
    }
}
