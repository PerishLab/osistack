use super::{Connection, Reaction};
use crate::frame::Frame;
use crate::stream::{Code, Fault, Misuse, Outcome};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Reset {
        stream: u32,
        code: u32,
    },
    Pong([u8; 8]),
    Goaway {
        last: u32,
        code: u32,
        debug: Vec<u8>,
        unprocessed: Vec<u32>,
    },
}

impl Connection {
    pub(super) fn noted(outcome: Outcome, notice: Option<Notice>) -> Reaction {
        Reaction {
            outcome,
            reply: Vec::new(),
            block: None,
            notice,
        }
    }

    pub(super) fn pinged(&mut self, ack: bool, data: [u8; 8]) -> Reaction {
        if !ack {
            let mut reaction = Self::noted(Outcome::Accept, None);
            reaction.reply.push(Frame::Ping { ack: true, data });
            return reaction;
        }
        let found = self.pings.iter().position(|sent| *sent == data);
        let notice = found.map(|at| {
            self.pings.remove(at);
            Notice::Pong(data)
        });
        Self::noted(Outcome::Accept, notice)
    }

    pub(super) fn farewell(
        &mut self,
        (last, code): (u32, u32),
        debug: &[u8],
    ) -> Result<Reaction, Fault> {
        if self.going.is_some_and(|before| last > before) {
            return Err(Fault::Connection {
                code: Code::Protocol,
            });
        }
        self.going = Some(last);
        let unprocessed = self.streams.abandon(last);
        for stream in &unprocessed {
            self.sync(*stream);
        }
        let notice = Notice::Goaway {
            last,
            code,
            debug: debug.to_vec(),
            unprocessed,
        };
        Ok(Self::noted(Outcome::Accept, Some(notice)))
    }

    pub(super) fn release(
        &mut self,
        frame: &Frame,
        (stream, code): (u32, u32),
    ) -> Result<Reaction, Fault> {
        let outcome = self.streams.receive(frame)?;
        self.sync(stream);
        let notice = (outcome == Outcome::Accept).then_some(Notice::Reset { stream, code });
        Ok(Self::noted(outcome, notice))
    }

    pub(super) fn depart(last: u32) -> Result<(), Misuse> {
        if last == 0 { Ok(()) } else { Err(Misuse::Last) }
    }
}
