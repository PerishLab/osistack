use super::Connection;
use super::Reaction;
use crate::assembly::{Assembly, LIMIT};
use crate::frame::Frame;
use crate::hpack::Header;
use crate::stream::{Code, Fault, Misuse, Outcome, State};

impl Connection {
    pub fn headers(
        &mut self,
        stream: u32,
        fields: &[Header],
        fin: bool,
    ) -> Result<Vec<Frame>, Misuse> {
        if self.outgoing.is_some() {
            return Err(Misuse::Block);
        }
        let probe = Frame::Headers {
            stream,
            fin,
            complete: true,
            pad: None,
            priority: None,
            block: Vec::new(),
        };
        self.admit(&probe, stream)?;
        let total: usize = fields.iter().map(Header::size).sum();
        if self.remote.header.is_some_and(|most| total > most as usize) {
            return Err(Misuse::Large);
        }
        let block = self.encoder.encode(fields);
        let frames = Self::split(stream, fin, (&block, self.remote.frame as usize));
        for frame in &frames {
            self.send(frame)?;
        }
        Ok(frames)
    }

    pub(super) fn cap(&self) -> usize {
        let declared = self.local.header;
        declared.map_or(LIMIT, |most| usize::try_from(most).unwrap_or(LIMIT))
    }

    pub(super) fn open(
        &mut self,
        frame: &Frame,
        (stream, fin, complete): (u32, bool, bool),
        block: &[u8],
    ) -> Result<Reaction, Fault> {
        let verdict = self.streams.receive(frame);
        if let Err(fault @ Fault::Connection { .. }) = verdict {
            return Err(fault);
        }
        self.sync(stream);
        let mut assembly = Assembly::new(stream, fin, verdict);
        assembly.push(block, self.cap())?;
        self.proceed(assembly, complete)
    }

    pub(super) fn extend(
        &mut self,
        (stream, complete): (u32, bool),
        block: &[u8],
    ) -> Result<Reaction, Fault> {
        let protocol = Fault::Connection {
            code: Code::Protocol,
        };
        let Some(mut assembly) = self.incoming.take() else {
            return Err(protocol);
        };
        if assembly.stream() != stream {
            return Err(protocol);
        }
        assembly.push(block, self.cap())?;
        self.proceed(assembly, complete)
    }

    pub(super) fn proceed(
        &mut self,
        assembly: Assembly,
        complete: bool,
    ) -> Result<Reaction, Fault> {
        if !complete {
            self.incoming = Some(assembly);
            return Ok(Self::plain(Outcome::Accept));
        }
        let (outcome, block) = assembly.finish(&mut self.decoder)?;
        Ok(Reaction {
            outcome,
            reply: Vec::new(),
            block,
            notice: None,
        })
    }

    pub(super) fn resume(&mut self, frame: &Frame, open: u32) -> Result<(), Misuse> {
        match frame {
            Frame::Continuation {
                stream, complete, ..
            } if *stream == open => {
                if *complete {
                    self.outgoing = None;
                }
                Ok(())
            }
            _ => Err(Misuse::Block),
        }
    }

    pub(super) fn split(stream: u32, fin: bool, (block, most): (&[u8], usize)) -> Vec<Frame> {
        let mut chunks: Vec<&[u8]> = block.chunks(most.max(1)).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let last = chunks.len() - 1;
        let make = |(at, bytes): (usize, &&[u8])| {
            let (complete, block) = (at == last, bytes.to_vec());
            if at == 0 {
                Frame::Headers {
                    stream,
                    fin,
                    complete,
                    pad: None,
                    priority: None,
                    block,
                }
            } else {
                Frame::Continuation {
                    stream,
                    complete,
                    block,
                }
            }
        };
        chunks.iter().enumerate().map(make).collect()
    }

    pub(super) fn admit(&self, frame: &Frame, stream: u32) -> Result<(), Misuse> {
        let fresh = !stream.is_multiple_of(2) && self.streams.state(stream) == State::Idle;
        let full = self.remote.streams.is_some_and(|most| {
            self.streams.active() >= usize::try_from(most).unwrap_or(usize::MAX)
        });
        if fresh && self.going.is_some() {
            return Err(Misuse::Going);
        }
        if fresh && full {
            return Err(Misuse::Limit);
        }
        self.streams.check(frame)
    }
}
