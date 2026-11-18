use crate::error::Error;
use crate::frame::{ACK, DONE, Dependency, FIN, Frame, MASK, PAD, Setting, URGENT};

pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const HEAD: usize = 9;
const LEAST: usize = 16384;
const MOST: usize = 0xff_ffff;

#[derive(Debug, Clone, Copy)]
pub struct Head {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
}

impl Head {
    pub fn admit(&self) -> Result<(), Error> {
        let fine = match self.kind {
            0..=3 | 9 => self.stream != 0,
            4 | 6 | 7 => self.stream == 0,
            _ => true,
        };
        if fine && self.stream <= MASK {
            Ok(())
        } else {
            Err(Error::Stream)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Codec {
    max: usize,
}

impl Default for Codec {
    fn default() -> Self {
        Self { max: LEAST }
    }
}

impl Codec {
    pub fn new(max: usize) -> Result<Self, Error> {
        if (LEAST..=MOST).contains(&max) {
            Ok(Self { max })
        } else {
            Err(Error::Setting)
        }
    }

    pub fn decode(&self, input: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
        if input.len() < HEAD {
            return Ok(None);
        }
        let length =
            usize::from(input[0]) << 16 | usize::from(input[1]) << 8 | usize::from(input[2]);
        if length > self.max {
            return Err(Error::Length);
        }
        let end = HEAD + length;
        if input.len() < end {
            return Ok(None);
        }
        let head = Head {
            kind: input[3],
            flags: input[4],
            stream: u32::from_be_bytes([input[5], input[6], input[7], input[8]]) & MASK,
        };
        head.admit()?;
        Ok(Some((Self::parse(&head, &input[HEAD..end])?, end)))
    }

    pub fn encode(&self, frame: &Frame) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        let head = Self::build(frame, &mut body)?;
        head.admit()?;
        if body.len() > self.max {
            return Err(Error::Length);
        }
        let mut out = Vec::with_capacity(HEAD + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.push(head.kind);
        out.push(head.flags);
        out.extend_from_slice(&head.stream.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
}

impl Codec {
    pub(crate) fn parse(head: &Head, payload: &[u8]) -> Result<Frame, Error> {
        let stream = head.stream;
        match head.kind {
            0 => {
                let (pad, data) = Self::unpad(head.flags, payload)?;
                Ok(Frame::Data {
                    stream,
                    fin: head.flags & FIN != 0,
                    pad,
                    data: data.to_vec(),
                })
            }
            1 => Self::headers(head, payload),
            2 => Ok(Frame::Priority {
                stream,
                dependency: Dependency::read(Self::fixed(payload)?),
            }),
            3 => Ok(Frame::Reset {
                stream,
                code: u32::from_be_bytes(*Self::fixed(payload)?),
            }),
            4 => Self::settings(head, payload),
            5 => Err(Error::Push),
            6 => Ok(Frame::Ping {
                ack: head.flags & ACK != 0,
                data: *Self::fixed(payload)?,
            }),
            7 => Self::goaway(payload),
            8 => Self::window(head, payload),
            9 => Ok(Frame::Continuation {
                stream,
                complete: head.flags & DONE != 0,
                block: payload.to_vec(),
            }),
            kind => Ok(Frame::Unknown {
                kind,
                flags: head.flags,
                stream,
                payload: payload.to_vec(),
            }),
        }
    }

    fn fixed<const N: usize>(payload: &[u8]) -> Result<&[u8; N], Error> {
        payload.try_into().map_err(|_| Error::Length)
    }

    fn unpad(flags: u8, payload: &[u8]) -> Result<(Option<u8>, &[u8]), Error> {
        if flags & PAD == 0 {
            return Ok((None, payload));
        }
        let (pad, rest) = payload.split_first().ok_or(Error::Length)?;
        let keep = rest
            .len()
            .checked_sub(usize::from(*pad))
            .ok_or(Error::Padding)?;
        Ok((Some(*pad), &rest[..keep]))
    }

    fn headers(head: &Head, payload: &[u8]) -> Result<Frame, Error> {
        let (pad, body) = Self::unpad(head.flags, payload)?;
        let (priority, block) = if head.flags & URGENT == 0 {
            (None, body)
        } else {
            let (lead, block) = body.split_at_checked(5).ok_or(Error::Length)?;
            (Some(Dependency::read(Self::fixed(lead)?)), block)
        };
        Ok(Frame::Headers {
            stream: head.stream,
            fin: head.flags & FIN != 0,
            complete: head.flags & DONE != 0,
            pad,
            priority,
            block: block.to_vec(),
        })
    }

    fn settings(head: &Head, payload: &[u8]) -> Result<Frame, Error> {
        let ack = head.flags & ACK != 0;
        if ack && !payload.is_empty() || !payload.len().is_multiple_of(6) {
            return Err(Error::Length);
        }
        let mut list = Vec::new();
        for chunk in payload.chunks_exact(6) {
            let setting = Setting {
                id: u16::from_be_bytes([chunk[0], chunk[1]]),
                value: u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]),
            };
            setting.check()?;
            list.push(setting);
        }
        Ok(Frame::Settings { ack, list })
    }

    fn goaway(payload: &[u8]) -> Result<Frame, Error> {
        let (lead, debug) = payload.split_at_checked(8).ok_or(Error::Length)?;
        let last = u32::from_be_bytes([lead[0], lead[1], lead[2], lead[3]]) & MASK;
        let code = u32::from_be_bytes([lead[4], lead[5], lead[6], lead[7]]);
        Ok(Frame::Goaway {
            last,
            code,
            debug: debug.to_vec(),
        })
    }

    fn window(head: &Head, payload: &[u8]) -> Result<Frame, Error> {
        let increment = u32::from_be_bytes(*Self::fixed(payload)?) & MASK;
        if increment == 0 {
            return Err(Error::Increment);
        }
        Ok(Frame::Window {
            stream: head.stream,
            increment,
        })
    }
}
