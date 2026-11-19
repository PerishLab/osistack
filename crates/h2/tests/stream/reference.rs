use crate::support::*;
use h2::{Code, Fault, Outcome, State, Streams};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Headers(bool),
    Data(bool),
    Reset,
    Priority,
    Window,
    More,
}

impl Kind {
    fn frame(self, stream: u32) -> h2::Frame {
        match self {
            Kind::Headers(fin) => Stream(stream).headers(fin),
            Kind::Data(fin) => Stream(stream).data(fin),
            Kind::Reset => Stream(stream).reset(),
            Kind::Priority => Stream(stream).priority(),
            Kind::Window => Stream(stream).window(),
            Kind::More => Stream(stream).more(),
        }
    }

    fn fin(self) -> bool {
        self == Kind::Headers(true) || self == Kind::Data(true)
    }

    fn tolerated(self) -> bool {
        self == Kind::Reset || self == Kind::Window
    }
}

#[derive(Default, Clone, Copy)]
struct Facts {
    opened: bool,
    finished: bool,
    ended: bool,
    aborted: bool,
    refused: bool,
}

impl Facts {
    fn closed(&self) -> bool {
        let both = self.finished && self.ended;
        both || self.aborted || self.refused
    }
}

#[derive(Default)]
struct Model {
    facts: BTreeMap<u32, Facts>,
    highest: u32,
}

impl Model {
    fn dead(&self, stream: u32) -> bool {
        let facts = self.facts.get(&stream).copied().unwrap_or_default();
        let skipped = stream % 2 == 1 && stream < self.highest && !facts.opened;
        facts.closed() || skipped
    }

    fn send(&mut self, stream: u32, kind: Kind) -> bool {
        if kind == Kind::Priority {
            return true;
        }
        if stream.is_multiple_of(2) {
            return false;
        }
        let dead = self.dead(stream);
        let facts = self.facts.entry(stream).or_default();
        if !facts.opened && !dead {
            if !matches!(kind, Kind::Headers(_)) {
                return false;
            }
            facts.opened = true;
            facts.finished = kind.fin();
            self.highest = self.highest.max(stream);
            return true;
        }
        if dead || (facts.finished && !kind.tolerated()) {
            return false;
        }
        facts.aborted |= kind == Kind::Reset;
        facts.finished |= kind.fin();
        true
    }

    fn receive(&mut self, stream: u32, kind: Kind) -> Result<Outcome, Fault> {
        if kind == Kind::Priority {
            return Ok(Outcome::Accept);
        }
        let dead = self.dead(stream);
        let facts = self.facts.entry(stream).or_default();
        let protocol = Fault::Connection {
            code: Code::Protocol,
        };
        if !facts.opened && !dead {
            return Err(protocol);
        }
        if dead && facts.aborted {
            return Ok(Outcome::Discard);
        }
        if dead && kind.tolerated() {
            return Ok(Outcome::Discard);
        }
        if dead {
            return Err(Fault::Connection { code: Code::Closed });
        }
        if facts.ended && kind != Kind::Window && kind != Kind::Reset {
            return Err(Fault::Stream {
                stream,
                code: Code::Closed,
            });
        }
        facts.refused |= kind == Kind::Reset;
        facts.ended |= kind.fin();
        Ok(Outcome::Accept)
    }

    fn live(&self) -> usize {
        let count = |(id, facts): &(&u32, &Facts)| facts.opened && !facts.closed() && **id > 0;
        self.facts.iter().filter(count).count()
    }
}

struct Dice(u64);

impl Dice {
    fn roll(&mut self, sides: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % sides
    }
}

fn kind(dice: &mut Dice) -> Kind {
    match dice.roll(10) {
        0 | 1 => Kind::Headers(false),
        2 => Kind::Headers(true),
        3 | 4 => Kind::Data(false),
        5 => Kind::Data(true),
        6 => Kind::Reset,
        7 => Kind::Priority,
        8 => Kind::Window,
        _ => Kind::More,
    }
}

fn coarse(state: State) -> bool {
    matches!(state, State::Open | State::Local | State::Remote)
}

#[test]
fn model() {
    for seed in 1..=40u64 {
        let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut streams = Streams::new();
        let mut model = Model::default();
        for _ in 0..2000 {
            let stream = [1, 3, 5, 7, 2][dice.roll(5) as usize];
            let kind = kind(&mut dice);
            let frame = kind.frame(stream);
            if dice.roll(2) == 0 {
                let want = model.send(stream, kind);
                assert_eq!(
                    streams.send(&frame).is_ok(),
                    want,
                    "{seed} {stream} {kind:?}"
                );
            } else {
                let want = model.receive(stream, kind);
                assert_eq!(streams.receive(&frame), want, "{seed} {stream} {kind:?}");
            }
            assert_eq!(streams.active(), model.live());
            let facts = model.facts.get(&stream).copied().unwrap_or_default();
            let live = facts.opened && !facts.closed();
            if stream % 2 == 1 {
                assert_eq!(coarse(streams.state(stream)), live, "{seed} {stream}");
            }
        }
    }
}
