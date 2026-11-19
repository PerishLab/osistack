use crate::fault::{Code, Fault};
use crate::settings::Settings;
use wire::{Reader, Varint, Writer};

const FRAME: Fault = Fault::Connection { code: Code::Frame };
const LOAD: Fault = Fault::Connection { code: Code::Load };
const INTERNAL: Fault = Fault::Connection {
    code: Code::Internal,
};
const UNEXPECTED: Fault = Fault::Connection {
    code: Code::Unexpected,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data(Vec<u8>),
    Headers(Vec<u8>),
    Cancel(u64),
    Settings(Settings),
    Promise { push: u64, block: Vec<u8> },
    Goaway(u64),
    Max(u64),
    Unknown { kind: u64, length: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub kind: u64,
    pub length: u64,
}

impl Head {
    pub fn read(input: &[u8]) -> Option<(Self, usize)> {
        let mut reader = Reader::new(input);
        let kind = reader.varint().ok()?.get();
        let length = reader.varint().ok()?.get();
        Some((Self { kind, length }, reader.at()))
    }

    pub fn buffered(&self) -> Result<bool, Fault> {
        match self.kind {
            0x0 | 0x1 | 0x3 | 0x4 | 0x5 | 0x7 | 0xd => Ok(true),
            0x2 | 0x6 | 0x8 | 0x9 => Err(UNEXPECTED),
            _ => Ok(false),
        }
    }
}

fn number(payload: &[u8]) -> Result<u64, Fault> {
    let mut reader = Reader::new(payload);
    let value = reader.varint().map_err(|_| FRAME)?.get();
    if reader.left() > 0 {
        return Err(FRAME);
    }
    Ok(value)
}

fn varint(value: u64) -> Result<Varint, Fault> {
    Varint::new(value).map_err(|_| INTERNAL)
}

impl Frame {
    pub fn decode(input: &[u8], limit: usize) -> Result<Option<(Self, usize)>, Fault> {
        let Some((head, used)) = Head::read(input) else {
            return Ok(None);
        };
        head.buffered()?;
        if head.length > limit as u64 {
            return Err(LOAD);
        }
        let total = used + head.length as usize;
        let Some(payload) = input.get(used..total) else {
            return Ok(None);
        };
        Ok(Some((Self::body(&head, payload)?, total)))
    }

    fn body(head: &Head, payload: &[u8]) -> Result<Self, Fault> {
        match head.kind {
            0x0 => Ok(Frame::Data(payload.to_vec())),
            0x1 => Ok(Frame::Headers(payload.to_vec())),
            0x3 => Ok(Frame::Cancel(number(payload)?)),
            0x4 => Ok(Frame::Settings(Settings::read(payload)?)),
            0x5 => {
                let mut reader = Reader::new(payload);
                let push = reader.varint().map_err(|_| FRAME)?.get();
                let block = reader.take(reader.left()).map_err(|_| FRAME)?.to_vec();
                Ok(Frame::Promise { push, block })
            }
            0x7 => Ok(Frame::Goaway(number(payload)?)),
            0xd => Ok(Frame::Max(number(payload)?)),
            kind => Ok(Frame::Unknown {
                kind,
                length: head.length,
            }),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Fault> {
        let (kind, payload) = self.parts()?;
        let mut writer = Writer::new();
        writer.varint(varint(kind)?);
        writer.varint(varint(payload.len() as u64)?);
        writer.put(&payload);
        Ok(writer.finish())
    }

    fn parts(&self) -> Result<(u64, Vec<u8>), Fault> {
        let number = |value: u64| {
            let mut writer = Writer::new();
            writer.varint(varint(value)?);
            Ok::<Vec<u8>, Fault>(writer.finish())
        };
        match self {
            Frame::Data(data) => Ok((0x0, data.clone())),
            Frame::Headers(block) => Ok((0x1, block.clone())),
            Frame::Cancel(push) => Ok((0x3, number(*push)?)),
            Frame::Settings(settings) => Ok((0x4, settings.write()?)),
            Frame::Promise { push, block } => {
                let mut payload = number(*push)?;
                payload.extend_from_slice(block);
                Ok((0x5, payload))
            }
            Frame::Goaway(last) => Ok((0x7, number(*last)?)),
            Frame::Max(push) => Ok((0xd, number(*push)?)),
            Frame::Unknown { kind, length } => {
                let head = Head {
                    kind: *kind,
                    length: *length,
                };
                if head.buffered().unwrap_or(true) || *length > u64::from(u32::MAX) {
                    return Err(INTERNAL);
                }
                Ok((*kind, vec![0; *length as usize]))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Framer {
    buffer: Vec<u8>,
    limit: usize,
    skip: u64,
    stream: bool,
    data: u64,
}

impl Framer {
    pub fn new(limit: usize) -> Self {
        Self {
            buffer: Vec::new(),
            limit,
            skip: 0,
            stream: false,
            data: 0,
        }
    }

    pub fn streaming(limit: usize) -> Self {
        Self {
            stream: true,
            ..Self::new(limit)
        }
    }

    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    pub fn complete(&self) -> bool {
        self.buffer.is_empty() && self.skip == 0 && self.data == 0
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, Fault> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.skip > 0 && !self.drop() {
                return Ok(frames);
            }
            if self.data > 0 {
                let Some(frame) = self.chunk() else {
                    return Ok(frames);
                };
                frames.push(frame);
                continue;
            }
            let Some((head, used)) = Head::read(&self.buffer) else {
                return Ok(frames);
            };
            if self.stream && head.kind == 0 {
                self.buffer.drain(..used);
                self.data = head.length;
                if head.length == 0 {
                    frames.push(Frame::Data(Vec::new()));
                }
            } else if head.buffered()? {
                let Some((frame, total)) = Frame::decode(&self.buffer, self.limit)? else {
                    return Ok(frames);
                };
                frames.push(frame);
                self.buffer.drain(..total);
            } else {
                frames.push(Frame::Unknown {
                    kind: head.kind,
                    length: head.length,
                });
                self.buffer.drain(..used);
                self.skip = head.length;
            }
        }
    }

    fn chunk(&mut self) -> Option<Frame> {
        let most = usize::try_from(self.data).unwrap_or(usize::MAX);
        let taken = self.buffer.len().min(most);
        if taken == 0 {
            return None;
        }
        let bytes: Vec<u8> = self.buffer.drain(..taken).collect();
        self.data -= taken as u64;
        Some(Frame::Data(bytes))
    }

    fn drop(&mut self) -> bool {
        let most = usize::try_from(self.skip).unwrap_or(usize::MAX);
        let dropped = self.buffer.len().min(most);
        self.buffer.drain(..dropped);
        self.skip -= dropped as u64;
        self.skip == 0
    }
}
