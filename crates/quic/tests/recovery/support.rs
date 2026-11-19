use quic::{Ack, Arrival, Frame, Mark, Recovery, Sent, Space};

pub fn packet(number: u64, time: u64) -> Sent {
    Sent {
        number,
        time,
        size: 1200,
        eliciting: true,
        flight: true,
    }
}

pub fn quiet(number: u64, time: u64) -> Sent {
    Sent {
        number,
        time,
        size: 40,
        eliciting: false,
        flight: false,
    }
}

pub fn arrival(serial: u64, time: u64) -> Arrival {
    marked(serial, time, Mark::Plain)
}

pub fn silent(serial: u64, time: u64) -> Arrival {
    Arrival {
        eliciting: false,
        ..arrival(serial, time)
    }
}

pub fn marked(number: u64, time: u64, mark: Mark) -> Arrival {
    Arrival {
        number,
        time,
        eliciting: true,
        mark,
    }
}

pub fn ack(largest: u64, first: u64) -> Ack {
    Ack {
        largest,
        delay: 0,
        first,
        ranges: Vec::new(),
        ecn: None,
    }
}

pub fn client() -> Recovery {
    let mut recovery = Recovery::new(false, 25_000, 3);
    recovery.confirm(0);
    recovery
}

pub fn burst(recovery: &mut Recovery, space: Space, count: u64, time: u64) {
    for number in 0..count {
        recovery.sent(space, packet(number, time));
    }
}

pub fn numbers(list: &[quic::Sent]) -> Vec<u64> {
    list.iter().map(|sent| sent.number).collect()
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

    pub fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }
}

pub fn trip(ack: &Ack) -> Ack {
    let bytes = Frame::join(&[Frame::Ack(ack.clone())]).unwrap();
    match Frame::all(&bytes).unwrap().remove(0) {
        Frame::Ack(found) => found,
        other => panic!("{other:?}"),
    }
}
