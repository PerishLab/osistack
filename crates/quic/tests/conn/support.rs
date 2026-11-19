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
}

pub fn token(seed: u64) -> [u8; 8] {
    seed.wrapping_mul(0x2545_f491_4f6c_dd1d).to_be_bytes()
}
