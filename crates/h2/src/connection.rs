use crate::codec::{Codec, PREFACE};
use crate::flow::Flow;
use crate::frame::Frame;
use crate::settings::Settings;
use crate::stream::{Code, Fault, Misuse, Outcome, State, Streams};
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    pub outcome: Outcome,
    pub reply: Vec<Frame>,
}

#[derive(Debug, Clone)]
pub struct Connection {
    local: Settings,
    remote: Settings,
    pending: VecDeque<Settings>,
    streams: Streams,
    flow: Flow,
    ready: bool,
}

impl Connection {
    pub fn start(wanted: Settings) -> (Self, Vec<u8>) {
        let proposal = Settings {
            push: false,
            ..wanted
        };
        let frame = Frame::Settings {
            ack: false,
            list: proposal.list(),
        };
        let mut bytes = PREFACE.to_vec();
        let encoded = Codec::default().encode(&frame);
        bytes.extend(encoded.expect("settings fit one frame"));
        let connection = Self {
            local: Settings::default(),
            remote: Settings::default(),
            pending: VecDeque::from([proposal]),
            streams: Streams::new(),
            flow: Flow::new(),
            ready: false,
        };
        (connection, bytes)
    }

    pub fn local(&self) -> &Settings {
        &self.local
    }

    pub fn remote(&self) -> &Settings {
        &self.remote
    }

    pub fn streams(&self) -> &Streams {
        &self.streams
    }

    pub fn flow(&self) -> &Flow {
        &self.flow
    }

    pub fn ready(&self) -> bool {
        self.ready
    }

    pub fn unacknowledged(&self) -> usize {
        self.pending.len()
    }

    pub fn inbound(&self) -> Codec {
        Codec::new(self.local.frame as usize).unwrap_or_default()
    }

    pub fn outbound(&self) -> Codec {
        Codec::new(self.remote.frame as usize).unwrap_or_default()
    }

    pub fn send(&mut self, frame: &Frame) -> Result<(), Misuse> {
        match frame {
            Frame::Settings { ack: true, .. } => Err(Misuse::Setting),
            Frame::Settings { list, .. } => self.propose(list),
            Frame::Headers { stream, .. } => self.begin(frame, *stream),
            Frame::Data { stream, .. } => self.transmit(frame, *stream),
            Frame::Window {
                stream, increment, ..
            } => {
                self.streams.send(frame)?;
                self.flow.grant(*stream, *increment)
            }
            Frame::Continuation { stream, .. }
            | Frame::Reset { stream, .. }
            | Frame::Priority { stream, .. } => {
                self.streams.send(frame)?;
                self.sync(*stream);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn receive(&mut self, frame: &Frame) -> Result<Reaction, Fault> {
        let protocol = Fault::Connection {
            code: Code::Protocol,
        };
        match frame {
            Frame::Settings { ack: false, list } => self.accept(list),
            _ if !self.ready => Err(protocol),
            Frame::Settings { .. } => self.confirm(),
            Frame::Data { stream, .. } => self.deliver(frame, *stream),
            Frame::Window {
                stream, increment, ..
            } => {
                let outcome = self.streams.receive(frame)?;
                self.flow.credit(*stream, *increment)?;
                Ok(Self::plain(outcome))
            }
            Frame::Headers { stream, .. }
            | Frame::Continuation { stream, .. }
            | Frame::Reset { stream, .. }
            | Frame::Priority { stream, .. } => {
                let outcome = self.streams.receive(frame)?;
                self.sync(*stream);
                Ok(Self::plain(outcome))
            }
            _ => Ok(Self::plain(Outcome::Accept)),
        }
    }

    fn plain(outcome: Outcome) -> Reaction {
        Reaction {
            outcome,
            reply: Vec::new(),
        }
    }

    fn propose(&mut self, list: &[crate::frame::Setting]) -> Result<(), Misuse> {
        let mut next = self.pending.back().unwrap_or(&self.local).clone();
        next.apply(list).map_err(|_| Misuse::Setting)?;
        next.push = false;
        self.pending.push_back(next);
        Ok(())
    }

    fn begin(&mut self, frame: &Frame, stream: u32) -> Result<(), Misuse> {
        let fresh = !stream.is_multiple_of(2) && self.streams.state(stream) == State::Idle;
        let full = self.remote.streams.is_some_and(|most| {
            self.streams.active() >= usize::try_from(most).unwrap_or(usize::MAX)
        });
        if fresh && full {
            return Err(Misuse::Limit);
        }
        self.streams.send(frame)?;
        self.sync(stream);
        Ok(())
    }

    fn transmit(&mut self, frame: &Frame, stream: u32) -> Result<(), Misuse> {
        let cost = Flow::cost(frame).unwrap_or(0);
        let tracked = self.flow.outgoing(stream).is_some();
        if tracked && cost > self.flow.room(stream) {
            return Err(Misuse::Window);
        }
        self.streams.send(frame)?;
        self.flow.send(stream, cost)?;
        self.sync(stream);
        Ok(())
    }

    fn accept(&mut self, list: &[crate::frame::Setting]) -> Result<Reaction, Fault> {
        let mut next = self.remote.clone();
        next.apply(list)?;
        next.push = false;
        self.flow.remote(next.window)?;
        self.remote = next;
        self.ready = true;
        Ok(Reaction {
            outcome: Outcome::Accept,
            reply: vec![Frame::Settings {
                ack: true,
                list: Vec::new(),
            }],
        })
    }

    fn confirm(&mut self) -> Result<Reaction, Fault> {
        let Some(next) = self.pending.pop_front() else {
            return Err(Fault::Connection {
                code: Code::Protocol,
            });
        };
        self.flow.local(next.window)?;
        self.local = next;
        Ok(Self::plain(Outcome::Accept))
    }

    fn deliver(&mut self, frame: &Frame, stream: u32) -> Result<Reaction, Fault> {
        let cost = Flow::cost(frame).unwrap_or(0);
        let charged = self.flow.receive(stream, cost);
        let seen = self.streams.receive(frame);
        self.sync(stream);
        match (seen, charged) {
            (Err(fault @ Fault::Connection { .. }), _) => Err(fault),
            (_, Err(fault @ Fault::Connection { .. })) => Err(fault),
            (Err(fault), _) | (_, Err(fault)) => Err(fault),
            (Ok(outcome), Ok(())) => Ok(Self::plain(outcome)),
        }
    }

    fn sync(&mut self, stream: u32) {
        match self.streams.state(stream) {
            State::Open | State::Local | State::Remote => self.flow.open(stream),
            State::Closed(_) => self.flow.close(stream),
            State::Idle => {}
        }
    }
}
