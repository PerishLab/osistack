use super::{Ack, Direction, Frame, Stream};
use crate::error::Error;
use crate::field::{Cursor, STREAMS, within};

impl Frame {
    pub fn parse(data: &[u8]) -> Result<(Self, usize), Error> {
        let mut reader = Cursor::new(data);
        let code = reader.varint()?;
        if code.size() != reader.at() {
            return Err(Error::Minimal);
        }
        let frame = match code.get() {
            0x00 => Self::padding(data, &mut reader)?,
            0x01 => Frame::Ping,
            0x02 | 0x03 => Frame::Ack(Ack::read(&mut reader, code.get() == 0x03)?),
            0x04..=0x07 => Self::basic(code.get(), &mut reader)?,
            0x08..=0x0f => Frame::Stream(Stream::read(&mut reader, code.get() as u8)?),
            0x10..=0x17 => Self::flow(code.get(), &mut reader)?,
            0x18..=0x1b => Self::ident(code.get(), &mut reader)?,
            0x1c..=0x1e => Self::close(code.get(), &mut reader)?,
            0x30 | 0x31 => return Err(Error::Excluded),
            _ => return Err(Error::Kind),
        };
        Ok((frame, reader.at()))
    }

    fn padding(data: &[u8], reader: &mut Cursor) -> Result<Self, Error> {
        let run = data[1..].iter().take_while(|byte| **byte == 0).count();
        reader.take(run)?;
        Ok(Frame::Padding(1 + run))
    }

    fn basic(code: u64, reader: &mut Cursor) -> Result<Self, Error> {
        Ok(match code {
            0x04 => Frame::Reset {
                stream: reader.big()?,
                code: reader.big()?,
                size: reader.big()?,
            },
            0x05 => Frame::Stop {
                stream: reader.big()?,
                code: reader.big()?,
            },
            0x06 => {
                let offset = reader.big()?;
                let data = reader.blob()?;
                Stream::span(offset, data.len())?;
                Frame::Crypto { offset, data }
            }
            _ => {
                let token = reader.blob()?;
                if token.is_empty() {
                    return Err(Error::Empty);
                }
                Frame::Token(token)
            }
        })
    }

    fn flow(code: u64, reader: &mut Cursor) -> Result<Self, Error> {
        let kind = if code & 1 == 0 {
            Direction::Bidi
        } else {
            Direction::Uni
        };
        Ok(match code {
            0x10 => Frame::Data(reader.big()?),
            0x11 => Frame::Window {
                stream: reader.big()?,
                limit: reader.big()?,
            },
            0x12 | 0x13 => Frame::Streams {
                kind,
                limit: within(reader.big()?, STREAMS)?,
            },
            0x14 => Frame::Blocked(reader.big()?),
            0x15 => Frame::Stalled {
                stream: reader.big()?,
                limit: reader.big()?,
            },
            _ => Frame::Choked {
                kind,
                limit: within(reader.big()?, STREAMS)?,
            },
        })
    }

    fn ident(code: u64, reader: &mut Cursor) -> Result<Self, Error> {
        Ok(match code {
            0x18 => {
                let sequence = reader.big()?;
                let retire = within(reader.big()?, sequence)?;
                let cid = reader.cid()?;
                let token = reader.array()?;
                Frame::Issue {
                    sequence,
                    retire,
                    cid,
                    token,
                }
            }
            0x19 => Frame::Retire(reader.big()?),
            0x1a => Frame::Challenge(reader.array()?),
            _ => Frame::Response(reader.array()?),
        })
    }

    fn close(code: u64, reader: &mut Cursor) -> Result<Self, Error> {
        Ok(match code {
            0x1c => Frame::Transport {
                code: reader.big()?,
                frame: reader.big()?,
                reason: reader.blob()?,
            },
            0x1d => Frame::Application {
                code: reader.big()?,
                reason: reader.blob()?,
            },
            _ => Frame::Done,
        })
    }
}
