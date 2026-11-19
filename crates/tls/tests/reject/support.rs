use tls::{Extension, Offer, Reply};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

#[derive(Clone)]
pub struct Parts {
    pub version: u16,
    pub session: Vec<u8>,
    pub suites: Vec<u8>,
    pub compression: Vec<u8>,
    pub extensions: Vec<u8>,
    pub tail: Vec<u8>,
}

impl Default for Parts {
    fn default() -> Self {
        Self {
            version: 0x0303,
            session: vec![7; 8],
            suites: hex("1301"),
            compression: vec![0],
            extensions: extension(0x0a, 4),
            tail: Vec::new(),
        }
    }
}

pub fn extension(kind: u16, size: usize) -> Vec<u8> {
    let mut bytes = kind.to_be_bytes().to_vec();
    bytes.extend((size as u16).to_be_bytes());
    bytes.extend(vec![9; size]);
    bytes
}

fn put(bytes: &mut Vec<u8>, part: &[u8], width: usize) {
    let length = (part.len() as u32).to_be_bytes();
    bytes.extend(&length[4 - width..]);
    bytes.extend(part);
}

impl Parts {
    pub fn offer(&self) -> Vec<u8> {
        let mut bytes = self.version.to_be_bytes().to_vec();
        bytes.extend([5u8; 32]);
        put(&mut bytes, &self.session, 1);
        put(&mut bytes, &self.suites, 2);
        put(&mut bytes, &self.compression, 1);
        put(&mut bytes, &self.extensions, 2);
        bytes.extend(&self.tail);
        bytes
    }

    pub fn reply(&self) -> Vec<u8> {
        let mut bytes = self.version.to_be_bytes().to_vec();
        bytes.extend([6u8; 32]);
        put(&mut bytes, &self.session, 1);
        bytes.extend(&self.suites[..2.min(self.suites.len())]);
        bytes.extend(&self.compression[..1.min(self.compression.len())]);
        put(&mut bytes, &self.extensions, 2);
        bytes.extend(&self.tail);
        bytes
    }
}

pub fn offered(extensions: Vec<Extension>) -> Offer {
    Offer {
        random: [5; 32],
        session: Vec::new(),
        suites: vec![0x1301],
        extensions,
    }
}

pub fn replied(extensions: Vec<Extension>) -> Reply {
    Reply {
        random: [6; 32],
        session: Vec::new(),
        suite: 0x1301,
        extensions,
    }
}

pub fn blob(kind: u16, size: usize) -> Extension {
    Extension {
        kind,
        data: vec![1; size],
    }
}
