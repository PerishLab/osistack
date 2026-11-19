use crate::frame::{Frame, MASK};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Close {
    Finished,
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Open,
    Local,
    Remote,
    Closed(Close),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Protocol,
    Flow,
    Closed,
}

impl Code {
    pub fn get(self) -> u32 {
        match self {
            Code::Protocol => 0x1,
            Code::Flow => 0x3,
            Code::Closed => 0x5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    Stream { stream: u32, code: Code },
    Connection { code: Code },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misuse {
    Zero,
    Parity,
    Idle,
    Half,
    Closed,
    Exhausted,
    Window,
    Increment,
    Setting,
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Data(bool),
    Headers(bool),
    Continuation,
    Reset,
    Priority,
    Window,
}

impl Event {
    fn of(frame: &Frame) -> Option<(u32, Event)> {
        match frame {
            Frame::Data { stream, fin, .. } => Some((*stream, Event::Data(*fin))),
            Frame::Headers { stream, fin, .. } => Some((*stream, Event::Headers(*fin))),
            Frame::Continuation { stream, .. } => Some((*stream, Event::Continuation)),
            Frame::Reset { stream, .. } => Some((*stream, Event::Reset)),
            Frame::Priority { stream, .. } => Some((*stream, Event::Priority)),
            Frame::Window { stream, .. } => Some((*stream, Event::Window)),
            _ => None,
        }
    }

    fn fin(self) -> bool {
        matches!(self, Event::Data(true) | Event::Headers(true))
    }
}

impl State {
    fn sent(self, stream: u32, event: Event) -> Result<State, Misuse> {
        match (self, event) {
            (State::Idle, Event::Headers(fin)) if stream % 2 == 1 => {
                Ok(if fin { State::Local } else { State::Open })
            }
            (State::Idle, _) if stream.is_multiple_of(2) => Err(Misuse::Parity),
            (State::Idle, _) => Err(Misuse::Idle),
            (State::Open | State::Local | State::Remote, Event::Reset) => {
                Ok(State::Closed(Close::Sent))
            }
            (State::Open, other) => Ok(if other.fin() {
                State::Local
            } else {
                State::Open
            }),
            (State::Remote, other) => Ok(if other.fin() {
                State::Closed(Close::Finished)
            } else {
                State::Remote
            }),
            (State::Local, Event::Window) => Ok(State::Local),
            (State::Local, _) => Err(Misuse::Half),
            (State::Closed(_), _) => Err(Misuse::Closed),
        }
    }

    fn received(self, stream: u32, event: Event) -> Result<(State, Outcome), Fault> {
        let protocol = Fault::Connection {
            code: Code::Protocol,
        };
        match (self, event) {
            (_, Event::Priority) => Ok((self, Outcome::Accept)),
            (State::Idle, _) => Err(protocol),
            (State::Open | State::Local | State::Remote, Event::Reset) => {
                Ok((State::Closed(Close::Received), Outcome::Accept))
            }
            (State::Open, other) => {
                let next = if other.fin() {
                    State::Remote
                } else {
                    State::Open
                };
                Ok((next, Outcome::Accept))
            }
            (State::Local, other) => {
                let next = if other.fin() {
                    State::Closed(Close::Finished)
                } else {
                    State::Local
                };
                Ok((next, Outcome::Accept))
            }
            (State::Remote, Event::Window) => Ok((State::Remote, Outcome::Accept)),
            (State::Remote, _) => Err(Fault::Stream {
                stream,
                code: Code::Closed,
            }),
            (State::Closed(Close::Sent), _) => Ok((self, Outcome::Discard)),
            (State::Closed(_), Event::Window | Event::Reset) => Ok((self, Outcome::Discard)),
            (State::Closed(_), _) => Err(Fault::Connection { code: Code::Closed }),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Streams {
    states: BTreeMap<u32, State>,
    highest: u32,
}

impl Streams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&self) -> Result<u32, Misuse> {
        let next = if self.highest == 0 {
            1
        } else {
            self.highest + 2
        };
        if next > MASK {
            return Err(Misuse::Exhausted);
        }
        Ok(next)
    }

    pub fn state(&self, stream: u32) -> State {
        if stream.is_multiple_of(2) || stream > self.highest {
            return State::Idle;
        }
        let known = self.states.get(&stream).copied();
        known.unwrap_or(State::Closed(Close::Finished))
    }

    pub fn active(&self) -> usize {
        let live = |state: &&State| matches!(state, State::Open | State::Local | State::Remote);
        self.states.values().filter(live).count()
    }

    pub fn send(&mut self, frame: &Frame) -> Result<(), Misuse> {
        let Some((stream, event)) = Event::of(frame) else {
            return Ok(());
        };
        if stream == 0 {
            return if event == Event::Window {
                Ok(())
            } else {
                Err(Misuse::Zero)
            };
        }
        if event == Event::Priority {
            return Ok(());
        }
        let next = self.state(stream).sent(stream, event)?;
        self.record(stream, next);
        Ok(())
    }

    pub fn receive(&mut self, frame: &Frame) -> Result<Outcome, Fault> {
        let Some((stream, event)) = Event::of(frame) else {
            return Ok(Outcome::Accept);
        };
        if stream == 0 {
            return match event {
                Event::Window => Ok(Outcome::Accept),
                _ => Err(Fault::Connection {
                    code: Code::Protocol,
                }),
            };
        }
        let (next, outcome) = self.state(stream).received(stream, event)?;
        self.record(stream, next);
        Ok(outcome)
    }

    fn record(&mut self, stream: u32, state: State) {
        if state == State::Idle {
            return;
        }
        self.highest = self.highest.max(stream);
        self.states.insert(stream, state);
    }
}
