use h3::{Code, Fault, Streams};

pub fn fault() -> Fault {
    Fault::Connection { code: Code::Id }
}

pub fn opened(count: usize) -> Streams {
    let mut streams = Streams::new();
    for _ in 0..count {
        streams.open().unwrap();
    }
    streams
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
