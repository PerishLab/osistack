use h3::{Code, Fault};

pub fn bytes(hex: &str) -> Vec<u8> {
    let clean: String = hex.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn connection(code: Code) -> Fault {
    Fault::Connection { code }
}

pub struct Dice(pub u64);

impl Dice {
    pub fn roll(&mut self, sides: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % sides
    }
}
