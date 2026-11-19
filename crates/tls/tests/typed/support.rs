use tls::{Extension, Message, Offer, Place, Record, Reply, Typed};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn body(source: &str, framed: bool) -> Vec<u8> {
    let mut wire = hex(source);
    if framed {
        let (record, used) = Record::parse(&wire).unwrap().unwrap();
        assert_eq!(used, wire.len());
        wire = record.fragment;
    }
    let (message, used) = Message::parse(&wire, 1 << 16).unwrap().unwrap();
    assert_eq!(used, wire.len());
    message.body
}

pub fn offered(capture: &str, framed: bool) -> Vec<Extension> {
    Offer::parse(&body(capture, framed)).unwrap().extensions
}

pub fn replied(sample: &str, framed: bool) -> Vec<Extension> {
    Reply::parse(&body(sample, framed)).unwrap().extensions
}

pub fn find(list: &[Extension], kind: u16) -> &Extension {
    list.iter().find(|found| found.kind == kind).unwrap()
}

pub fn check(list: &[Extension], kind: u16, place: Place, expected: Typed) {
    let found = find(list, kind);
    assert_eq!(
        Typed::parse(found, place),
        Ok(Some(expected.clone())),
        "{kind}"
    );
    assert_eq!(&expected.write().unwrap(), found, "{kind}");
}

pub fn blank(list: &[Extension], kind: u16, place: Place) {
    assert_eq!(Typed::parse(find(list, kind), place), Ok(None), "{kind}");
}

pub fn extension(kind: u16, text: &str) -> Extension {
    Extension {
        kind,
        data: hex(text),
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
