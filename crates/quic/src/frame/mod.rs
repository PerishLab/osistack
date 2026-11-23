mod ack;
mod opening;
mod read;
mod stream;
mod write;

use crate::error::Error;

pub use ack::{Ack, Ecn};
pub use opening::Opening;
pub use stream::Stream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Bidi,
    Uni,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    Ping,
    Ack(Ack),
    Reset {
        stream: u64,
        code: u64,
        size: u64,
    },
    Stop {
        stream: u64,
        code: u64,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    Token(Vec<u8>),
    Stream(Stream),
    Data(u64),
    Window {
        stream: u64,
        limit: u64,
    },
    Streams {
        kind: Direction,
        limit: u64,
    },
    Blocked(u64),
    Stalled {
        stream: u64,
        limit: u64,
    },
    Choked {
        kind: Direction,
        limit: u64,
    },
    Issue {
        sequence: u64,
        retire: u64,
        cid: Vec<u8>,
        token: [u8; 16],
    },
    Retire(u64),
    Challenge([u8; 8]),
    Response([u8; 8]),
    Transport {
        code: u64,
        frame: u64,
        reason: Vec<u8>,
    },
    Application {
        code: u64,
        reason: Vec<u8>,
    },
    Done,
}

impl Frame {
    pub fn all(payload: &[u8]) -> Result<Vec<Frame>, Error> {
        let mut found = Vec::new();
        let mut at = 0;
        while at < payload.len() {
            let (frame, used) = Frame::parse(&payload[at..])?;
            found.push(frame);
            at += used;
        }
        Ok(found)
    }

    pub fn join(frames: &[Frame]) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        for (at, frame) in frames.iter().enumerate() {
            let open = matches!(frame, Frame::Stream(Stream { sized: false, .. }));
            if open && at + 1 != frames.len() {
                return Err(Error::Value);
            }
            bytes.extend(frame.write()?);
        }
        Ok(bytes)
    }
}
