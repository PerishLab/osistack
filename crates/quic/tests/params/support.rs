use quic::{Address, Error, Param, Params};

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

pub const TOKEN: &str = "00112233445566778899aabbccddeeff";

pub fn same(text: &str, params: &[Param]) {
    let bytes = hex(text);
    let found = Params::parse(&bytes).unwrap();
    assert_eq!(found.list, params, "{text}");
    assert_eq!(found.write().unwrap(), bytes, "{text}");
}

pub fn fails(text: &str, error: Error) {
    assert_eq!(Params::parse(&hex(text)), Err(error), "{text}");
}

pub fn cut() -> Error {
    Error::Wire(wire::Error::Truncated)
}

pub fn write(list: Vec<Param>) -> Result<Vec<u8>, Error> {
    Params { list }.write()
}

pub fn address(cid: &[u8]) -> Address {
    Address {
        v4: [127, 0, 0, 1],
        port4: 8080,
        v6: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port6: 8081,
        cid: cid.to_vec(),
        token: hex(TOKEN).try_into().unwrap(),
    }
}
