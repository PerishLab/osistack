use super::{Direction, Frame};
use crate::error::Error;
use crate::field::{STREAMS, ident, pack, put, within};
use wire::Writer;

impl Frame {
    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new();
        match self {
            Frame::Padding(0) => return Err(Error::Value),
            Frame::Padding(count) => writer.put(&vec![0u8; *count]),
            Frame::Ping => writer.byte(0x01),
            Frame::Ack(ack) => ack.write(&mut writer)?,
            Frame::Stream(stream) => stream.write(&mut writer)?,
            Frame::Done => writer.byte(0x1e),
            _ => self.other(&mut writer)?,
        }
        Ok(writer.finish())
    }

    fn other(&self, writer: &mut Writer) -> Result<(), Error> {
        match self {
            Frame::Reset { stream, code, size } => {
                Self::put(writer, 0x04, &[*stream, *code, *size])
            }
            Frame::Stop { stream, code } => Self::put(writer, 0x05, &[*stream, *code]),
            Frame::Crypto { offset, data } => {
                super::Stream::span(*offset, data.len())?;
                Self::put(writer, 0x06, &[*offset])?;
                pack(writer, data)
            }
            Frame::Token(token) if token.is_empty() => Err(Error::Empty),
            Frame::Token(token) => {
                writer.byte(0x07);
                pack(writer, token)
            }
            _ => self.gates(writer),
        }
    }

    fn gates(&self, writer: &mut Writer) -> Result<(), Error> {
        match self {
            Frame::Data(limit) => Self::put(writer, 0x10, &[*limit]),
            Frame::Window { stream, limit } => Self::put(writer, 0x11, &[*stream, *limit]),
            Frame::Streams { kind, limit } => {
                Self::put(writer, 0x12 + Self::bit(*kind), &[within(*limit, STREAMS)?])
            }
            Frame::Blocked(limit) => Self::put(writer, 0x14, &[*limit]),
            Frame::Stalled { stream, limit } => Self::put(writer, 0x15, &[*stream, *limit]),
            Frame::Choked { kind, limit } => {
                Self::put(writer, 0x16 + Self::bit(*kind), &[within(*limit, STREAMS)?])
            }
            _ => self.names(writer),
        }
    }

    fn names(&self, writer: &mut Writer) -> Result<(), Error> {
        match self {
            Frame::Issue {
                sequence,
                retire,
                cid,
                token,
            } => {
                within(*retire, *sequence)?;
                Self::put(writer, 0x18, &[*sequence, *retire])?;
                ident(writer, cid)?;
                writer.put(token);
                Ok(())
            }
            Frame::Retire(sequence) => Self::put(writer, 0x19, &[*sequence]),
            Frame::Challenge(data) => {
                writer.byte(0x1a);
                writer.put(data);
                Ok(())
            }
            Frame::Response(data) => {
                writer.byte(0x1b);
                writer.put(data);
                Ok(())
            }
            Frame::Transport {
                code,
                frame,
                reason,
            } => {
                Self::put(writer, 0x1c, &[*code, *frame])?;
                pack(writer, reason)
            }
            Frame::Application { code, reason } => {
                Self::put(writer, 0x1d, &[*code])?;
                pack(writer, reason)
            }
            _ => Err(Error::Kind),
        }
    }

    fn put(writer: &mut Writer, code: u8, values: &[u64]) -> Result<(), Error> {
        writer.byte(code);
        for value in values {
            put(writer, *value)?;
        }
        Ok(())
    }

    fn bit(kind: Direction) -> u8 {
        u8::from(kind == Direction::Uni)
    }
}
