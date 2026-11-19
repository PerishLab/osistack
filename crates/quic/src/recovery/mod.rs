mod ack;
mod amplify;
mod close;
mod idle;
mod path;
mod receive;
mod reno;
mod rtt;
mod timer;

use std::collections::BTreeMap;

pub use amplify::Amplify;
pub use close::{Life, Mode, stateless};
pub use idle::Idle;
pub use path::{Echo, MINIMUM, Path, Probe, Validity};
pub use receive::{Arrival, Mark, Received, Seen};
pub use reno::Reno;
pub use rtt::{GRANULARITY, INITIAL, Rtt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    Initial,
    Handshake,
    Data,
}

impl Space {
    const ALL: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];

    fn slot(self) -> usize {
        match self {
            Space::Initial => 0,
            Space::Handshake => 1,
            Space::Data => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub number: u64,
    pub time: u64,
    pub size: u64,
    pub eliciting: bool,
    pub flight: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub acked: Vec<Sent>,
    pub lost: Vec<Sent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fired {
    Lost(Space, Vec<Sent>),
    Probe(Space),
    Anti(Space),
}

#[derive(Debug, Clone, Default)]
struct Lane {
    sent: BTreeMap<u64, Sent>,
    largest: Option<u64>,
    last: Option<u64>,
    loss: Option<u64>,
}

impl Lane {
    fn live(&self) -> bool {
        self.sent.values().any(|p| p.eliciting && p.flight)
    }
}

#[derive(Debug, Clone)]
pub struct Recovery {
    rtt: Rtt,
    lanes: [Lane; 3],
    pto: u32,
    delay: u64,
    exponent: u64,
    validated: bool,
    confirmed: bool,
    keys: bool,
    blocked: bool,
    timer: Option<u64>,
}

impl Recovery {
    pub fn new(server: bool, delay: u64, exponent: u64) -> Self {
        Self {
            rtt: Rtt::new(),
            lanes: Default::default(),
            pto: 0,
            delay,
            exponent,
            validated: server,
            confirmed: false,
            keys: false,
            blocked: false,
            timer: None,
        }
    }

    pub fn keys(&mut self) {
        self.keys = true;
    }

    pub fn confirm(&mut self, now: u64) {
        self.confirmed = true;
        self.validated = true;
        self.arm(now);
    }

    pub fn limit(&mut self, now: u64, blocked: bool) {
        self.blocked = blocked;
        self.arm(now);
    }

    pub fn sent(&mut self, space: Space, packet: Sent) {
        let time = packet.time;
        let lane = &mut self.lanes[space.slot()];
        let marked = packet.flight && packet.eliciting;
        let counted = packet.flight;
        lane.sent.insert(packet.number, packet);
        if marked {
            lane.last = Some(time);
        }
        if counted {
            self.arm(time);
        }
    }

    pub fn deadline(&self) -> Option<u64> {
        self.timer
    }

    pub fn rtt(&self) -> &Rtt {
        &self.rtt
    }

    pub fn pto(&self) -> u32 {
        self.pto
    }

    pub fn loss(&self, space: Space) -> Option<u64> {
        self.lanes[space.slot()].loss
    }
}
