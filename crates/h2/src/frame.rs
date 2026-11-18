use crate::codec::{Codec, Head};
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dependency {
    pub exclusive: bool,
    pub stream: u32,
    pub weight: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        stream: u32,
        fin: bool,
        pad: Option<u8>,
        data: Vec<u8>,
    },
    Headers {
        stream: u32,
        fin: bool,
        complete: bool,
        pad: Option<u8>,
        priority: Option<Dependency>,
        block: Vec<u8>,
    },
    Priority {
        stream: u32,
        dependency: Dependency,
    },
    Reset {
        stream: u32,
        code: u32,
    },
    Settings {
        ack: bool,
        list: Vec<Setting>,
    },
    Ping {
        ack: bool,
        data: [u8; 8],
    },
    Goaway {
        last: u32,
        code: u32,
        debug: Vec<u8>,
    },
    Window {
        stream: u32,
        increment: u32,
    },
    Continuation {
        stream: u32,
        complete: bool,
        block: Vec<u8>,
    },
    Unknown {
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    },
}

pub const MASK: u32 = 0x7fff_ffff;
pub const FIN: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const DONE: u8 = 0x4;
pub const PAD: u8 = 0x8;
pub const URGENT: u8 = 0x20;

impl Dependency {
    pub fn read(bytes: &[u8; 5]) -> Self {
        let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Self {
            exclusive: word >> 31 == 1,
            stream: word & MASK,
            weight: bytes[4],
        }
    }

    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.stream > MASK {
            return Err(Error::Stream);
        }
        let word = self.stream | u32::from(self.exclusive) << 31;
        out.extend_from_slice(&word.to_be_bytes());
        out.push(self.weight);
        Ok(())
    }
}

impl Setting {
    pub fn check(&self) -> Result<(), Error> {
        let fits = match self.id {
            2 => self.value <= 1,
            4 => self.value <= MASK,
            5 => (16384..=0xff_ffff).contains(&self.value),
            _ => true,
        };
        if fits { Ok(()) } else { Err(Error::Setting) }
    }
}

impl Codec {
    pub(crate) fn build(frame: &Frame, body: &mut Vec<u8>) -> Result<Head, Error> {
        match frame {
            Frame::Data {
                stream,
                fin,
                pad,
                data,
            } => {
                Self::padded(body, *pad, data);
                Ok(Head {
                    kind: 0,
                    flags: Self::flag(FIN, *fin) | Self::flag(PAD, pad.is_some()),
                    stream: *stream,
                })
            }
            Frame::Headers {
                stream,
                fin,
                complete,
                pad,
                priority,
                block,
            } => {
                let mut inner = Vec::new();
                if let Some(dependency) = priority {
                    dependency.write(&mut inner)?;
                }
                inner.extend_from_slice(block);
                Self::padded(body, *pad, &inner);
                Ok(Head {
                    kind: 1,
                    flags: Self::flag(FIN, *fin)
                        | Self::flag(DONE, *complete)
                        | Self::flag(PAD, pad.is_some())
                        | Self::flag(URGENT, priority.is_some()),
                    stream: *stream,
                })
            }
            Frame::Priority { stream, dependency } => {
                dependency.write(body)?;
                Ok(Self::head(2, 0, *stream))
            }
            Frame::Reset { stream, code } => {
                body.extend_from_slice(&code.to_be_bytes());
                Ok(Self::head(3, 0, *stream))
            }
            Frame::Settings { ack, list } => {
                if *ack && !list.is_empty() {
                    return Err(Error::Length);
                }
                for setting in list {
                    setting.check()?;
                    body.extend_from_slice(&setting.id.to_be_bytes());
                    body.extend_from_slice(&setting.value.to_be_bytes());
                }
                Ok(Self::head(4, Self::flag(ACK, *ack), 0))
            }
            Frame::Ping { ack, data } => {
                body.extend_from_slice(data);
                Ok(Self::head(6, Self::flag(ACK, *ack), 0))
            }
            Frame::Goaway { last, code, debug } => {
                if *last > MASK {
                    return Err(Error::Stream);
                }
                body.extend_from_slice(&last.to_be_bytes());
                body.extend_from_slice(&code.to_be_bytes());
                body.extend_from_slice(debug);
                Ok(Self::head(7, 0, 0))
            }
            Frame::Window { stream, increment } => {
                if *increment == 0 || *increment > MASK {
                    return Err(Error::Increment);
                }
                body.extend_from_slice(&increment.to_be_bytes());
                Ok(Self::head(8, 0, *stream))
            }
            Frame::Continuation {
                stream,
                complete,
                block,
            } => {
                body.extend_from_slice(block);
                Ok(Self::head(9, Self::flag(DONE, *complete), *stream))
            }
            Frame::Unknown {
                kind,
                flags,
                stream,
                payload,
            } => {
                if *kind <= 9 {
                    return Err(Error::Kind);
                }
                body.extend_from_slice(payload);
                Ok(Self::head(*kind, *flags, *stream))
            }
        }
    }

    fn head(kind: u8, flags: u8, stream: u32) -> Head {
        Head {
            kind,
            flags,
            stream,
        }
    }

    fn flag(bit: u8, on: bool) -> u8 {
        if on { bit } else { 0 }
    }

    fn padded(body: &mut Vec<u8>, pad: Option<u8>, inner: &[u8]) {
        if let Some(count) = pad {
            body.push(count);
        }
        body.extend_from_slice(inner);
        body.resize(body.len() + usize::from(pad.unwrap_or(0)), 0);
    }
}
