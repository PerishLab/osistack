#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn size(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    pub fn block(self) -> usize {
        match self {
            Hash::Sha256 => 64,
            Hash::Sha384 | Hash::Sha512 => 128,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut running = Running::new(self);
        running.update(data);
        running.finish()
    }
}

#[derive(Clone)]
pub enum Running {
    Sha256(radicula::Sha256),
    Sha384(radicula::Sha384),
    Sha512(radicula::Sha512),
}

impl Running {
    pub fn new(hash: Hash) -> Self {
        match hash {
            Hash::Sha256 => Running::Sha256(radicula::Sha256::new()),
            Hash::Sha384 => Running::Sha384(radicula::Sha384::new()),
            Hash::Sha512 => Running::Sha512(radicula::Sha512::new()),
        }
    }

    pub fn hash(&self) -> Hash {
        match self {
            Running::Sha256(_) => Hash::Sha256,
            Running::Sha384(_) => Hash::Sha384,
            Running::Sha512(_) => Hash::Sha512,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Running::Sha256(state) => state.update(data),
            Running::Sha384(state) => state.update(data),
            Running::Sha512(state) => state.update(data),
        }
    }

    pub fn peek(&self) -> Vec<u8> {
        self.clone().finish()
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Running::Sha256(state) => state.finish().to_vec(),
            Running::Sha384(state) => state.finish().to_vec(),
            Running::Sha512(state) => state.finish().to_vec(),
        }
    }
}
