use crate::Control;
use crate::fault::{Code, Fault};
use crate::frame::{Frame, Framer};
use crate::qpack::{Encoder, Field};
use crate::settings::Settings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Headers(Vec<u8>),
    Trailers(Vec<u8>),
    Data(Vec<u8>),
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misuse {
    Order,
    Closed,
    Empty,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Head,
    Body,
    Done,
}

#[derive(Debug, Clone)]
pub struct Request {
    framer: Framer,
    got: Phase,
    put: Phase,
    closed: bool,
}

fn fault(code: Code) -> Fault {
    Fault::Connection { code }
}

impl Request {
    pub fn new(limit: usize) -> Self {
        Self {
            framer: Framer::streaming(limit),
            got: Phase::Idle,
            put: Phase::Idle,
            closed: false,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Fault> {
        let mut events = Vec::new();
        for frame in self.framer.feed(bytes)? {
            events.extend(self.accept(frame)?);
        }
        Ok(events)
    }

    pub fn end(&mut self) -> Result<Event, Fault> {
        if self.framer.complete() {
            Ok(Event::End)
        } else {
            Err(fault(Code::Frame))
        }
    }

    pub fn headers(&mut self, block: &[u8]) -> Result<Vec<u8>, Misuse> {
        self.step(false)?;
        Frame::Headers(block.to_vec())
            .encode()
            .map_err(|_| Misuse::Large)
    }

    pub fn data(&mut self, data: &[u8]) -> Result<Vec<u8>, Misuse> {
        self.step(true)?;
        Frame::Data(data.to_vec())
            .encode()
            .map_err(|_| Misuse::Large)
    }

    pub fn finish(&mut self) -> Result<(), Misuse> {
        if self.closed {
            return Err(Misuse::Closed);
        }
        if self.put == Phase::Idle {
            return Err(Misuse::Empty);
        }
        self.closed = true;
        Ok(())
    }

    fn step(&mut self, data: bool) -> Result<(), Misuse> {
        if self.closed {
            return Err(Misuse::Closed);
        }
        self.put = match (self.put, data) {
            (Phase::Idle, false) => Phase::Head,
            (Phase::Head | Phase::Body, false) => Phase::Done,
            (Phase::Head | Phase::Body, true) => Phase::Body,
            _ => return Err(Misuse::Order),
        };
        Ok(())
    }

    fn accept(&mut self, frame: Frame) -> Result<Option<Event>, Fault> {
        match (self.got, frame) {
            (_, Frame::Unknown { .. }) => Ok(None),
            (_, Frame::Promise { .. }) => Err(fault(Code::Id)),
            (Phase::Idle | Phase::Head, Frame::Headers(block)) => {
                self.got = Phase::Head;
                Ok(Some(Event::Headers(block)))
            }
            (Phase::Body, Frame::Headers(block)) => {
                self.got = Phase::Done;
                Ok(Some(Event::Trailers(block)))
            }
            (Phase::Head | Phase::Body, Frame::Data(data)) => {
                self.got = Phase::Body;
                Ok(Some(Event::Data(data)))
            }
            _ => Err(fault(Code::Unexpected)),
        }
    }
}

pub struct Call {
    request: Request,
}

impl Call {
    pub fn control(settings: &Settings) -> Result<Vec<u8>, Fault> {
        Control::open(settings)
    }

    pub fn new(limit: usize) -> Self {
        Self {
            request: Request::new(limit),
        }
    }

    pub fn headers(&mut self, fields: &[Field]) -> Result<Vec<u8>, Misuse> {
        self.request.headers(&Encoder::new(true).encode(fields))
    }

    pub fn data(&mut self, data: &[u8]) -> Result<Vec<u8>, Misuse> {
        self.request.data(data)
    }

    pub fn finish(&mut self) -> Result<(), Misuse> {
        self.request.finish()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Fault> {
        self.request.feed(bytes)
    }

    pub fn end(&mut self) -> Result<Event, Fault> {
        self.request.end()
    }
}
