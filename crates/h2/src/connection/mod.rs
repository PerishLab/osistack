mod control;
mod headers;

pub use control::Notice;

use crate::assembly::{Assembly, Block};
use crate::codec::{Codec, PREFACE};
use crate::error::Error;
use crate::flow::Flow;
use crate::frame::Frame;
use crate::hpack::{Decoder, Encoder};
use crate::settings::Settings;
use crate::stream::{Code, Fault, Misuse, Outcome, State, Streams};
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    pub outcome: Outcome,
    pub reply: Vec<Frame>,
    pub block: Option<Block>,
    pub notice: Option<Notice>,
}

#[derive(Debug, Clone)]
pub struct Connection {
    local: Settings,
    remote: Settings,
    pending: VecDeque<Settings>,
    streams: Streams,
    flow: Flow,
    ready: bool,
    pings: Vec<[u8; 8]>,
    going: Option<u32>,
    incoming: Option<Assembly>,
    outgoing: Option<u32>,
    decoder: Decoder,
    encoder: Encoder,
}

impl Connection {
    pub fn start(wanted: Settings) -> Result<(Self, Vec<u8>), Error> {
        let proposal = Settings {
            push: false,
            ..wanted
        };
        let frame = Frame::Settings {
            ack: false,
            list: proposal.list(),
        };
        let mut bytes = PREFACE.to_vec();
        bytes.extend(Codec::default().encode(&frame)?);
        let connection = Self {
            local: Settings::default(),
            remote: Settings::default(),
            pending: VecDeque::from([proposal]),
            streams: Streams::new(),
            flow: Flow::new(),
            ready: false,
            pings: Vec::new(),
            going: None,
            incoming: None,
            outgoing: None,
            decoder: Decoder::new(4096),
            encoder: Encoder::new(4096, true),
        };
        Ok((connection, bytes))
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

    pub fn decoder(&self) -> &Decoder {
        &self.decoder
    }

    pub fn encoder(&self) -> &Encoder {
        &self.encoder
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
        if let Some(open) = self.outgoing {
            return self.resume(frame, open);
        }
        match frame {
            Frame::Settings { ack: true, .. } => Err(Misuse::Setting),
            Frame::Settings { list, .. } => self.propose(list),
            Frame::Headers {
                stream, complete, ..
            } => {
                self.begin(frame, *stream)?;
                if !complete {
                    self.outgoing = Some(*stream);
                }
                Ok(())
            }
            Frame::Continuation { .. } => Err(Misuse::Block),
            Frame::Ping {
                ack: false, data, ..
            } => {
                self.pings.push(*data);
                Ok(())
            }
            Frame::Goaway { last, .. } => Self::depart(*last),
            Frame::Data { stream, .. } => self.transmit(frame, *stream),
            Frame::Window {
                stream, increment, ..
            } => {
                self.streams.send(frame)?;
                self.flow.grant(*stream, *increment)
            }
            Frame::Reset { stream, .. } | Frame::Priority { stream, .. } => {
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
            _ if self.incoming.is_some() && !matches!(frame, Frame::Continuation { .. }) => {
                Err(protocol)
            }
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
            Frame::Headers {
                stream,
                fin,
                complete,
                block,
                ..
            } => self.open(frame, (*stream, *fin, *complete), block),
            Frame::Continuation {
                stream,
                complete,
                block,
            } => self.extend((*stream, *complete), block),
            Frame::Reset { stream, code } => self.release(frame, (*stream, *code)),
            Frame::Priority { stream, .. } => {
                let outcome = self.streams.receive(frame)?;
                self.sync(*stream);
                Ok(Self::plain(outcome))
            }
            Frame::Ping { ack, data } => Ok(self.pinged(*ack, *data)),
            Frame::Goaway { last, code, debug } => self.farewell((*last, *code), debug),
            _ => Ok(Self::plain(Outcome::Accept)),
        }
    }

    fn plain(outcome: Outcome) -> Reaction {
        Reaction {
            outcome,
            reply: Vec::new(),
            block: None,
            notice: None,
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
        self.admit(frame, stream)?;
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
        if next.table != self.remote.table {
            self.encoder.resize(next.table as usize);
        }
        self.remote = next;
        self.ready = true;
        Ok(Reaction {
            outcome: Outcome::Accept,
            reply: vec![Frame::Settings {
                ack: true,
                list: Vec::new(),
            }],
            block: None,
            notice: None,
        })
    }

    fn confirm(&mut self) -> Result<Reaction, Fault> {
        let Some(next) = self.pending.pop_front() else {
            return Err(Fault::Connection {
                code: Code::Protocol,
            });
        };
        self.flow.local(next.window)?;
        if next.table != self.local.table {
            self.decoder.resize(next.table as usize);
        }
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
