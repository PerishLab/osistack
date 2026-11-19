use crate::frame::{Frame, MASK};
use crate::stream::{Code, Fault, Misuse};
use std::collections::BTreeMap;

pub const INITIAL: u32 = 65_535;

const LIMIT: i64 = MASK as i64;

#[derive(Debug, Clone, Copy)]
struct Pair {
    out: i64,
    inn: i64,
}

#[derive(Debug, Clone)]
pub struct Flow {
    connection: Pair,
    streams: BTreeMap<u32, Pair>,
    ours: i64,
    theirs: i64,
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

impl Flow {
    pub fn new() -> Self {
        let start = i64::from(INITIAL);
        Self {
            connection: Pair {
                out: start,
                inn: start,
            },
            streams: BTreeMap::new(),
            ours: start,
            theirs: start,
        }
    }

    pub fn cost(frame: &Frame) -> Option<u32> {
        match frame {
            Frame::Data { pad, data, .. } => {
                let padding = pad.map_or(0, |length| usize::from(length) + 1);
                u32::try_from(data.len() + padding).ok()
            }
            _ => None,
        }
    }

    pub fn open(&mut self, stream: u32) {
        let pair = Pair {
            out: self.theirs,
            inn: self.ours,
        };
        self.streams.entry(stream).or_insert(pair);
    }

    pub fn close(&mut self, stream: u32) {
        self.streams.remove(&stream);
    }

    pub fn outgoing(&self, stream: u32) -> Option<i64> {
        self.pair(stream).map(|pair| pair.out)
    }

    pub fn incoming(&self, stream: u32) -> Option<i64> {
        self.pair(stream).map(|pair| pair.inn)
    }

    pub fn room(&self, stream: u32) -> u32 {
        let bound = self.pair(stream).map_or(0, |pair| pair.out);
        let room = self.connection.out.min(bound).max(0);
        u32::try_from(room).unwrap_or(0)
    }

    pub fn send(&mut self, stream: u32, length: u32) -> Result<(), Misuse> {
        if stream == 0 {
            return Err(Misuse::Zero);
        }
        let spent = i64::from(length);
        let pair = self.streams.get(&stream).ok_or(Misuse::Closed)?;
        if spent > self.connection.out.min(pair.out).max(0) {
            return Err(Misuse::Window);
        }
        self.connection.out -= spent;
        if let Some(pair) = self.streams.get_mut(&stream) {
            pair.out -= spent;
        }
        Ok(())
    }

    pub fn receive(&mut self, stream: u32, length: u32) -> Result<(), Fault> {
        let spent = i64::from(length);
        if spent > self.connection.inn {
            return Err(Fault::Connection { code: Code::Flow });
        }
        self.connection.inn -= spent;
        match self.streams.get_mut(&stream) {
            Some(pair) if spent > pair.inn => Err(Fault::Stream {
                stream,
                code: Code::Flow,
            }),
            Some(pair) => {
                pair.inn -= spent;
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn credit(&mut self, stream: u32, increment: u32) -> Result<(), Fault> {
        let fault = Self::fault(stream);
        if increment == 0 {
            return Err(fault(Code::Protocol));
        }
        let added = i64::from(increment);
        let Some(window) = self.window(stream, true) else {
            return Ok(());
        };
        if *window + added > LIMIT {
            return Err(fault(Code::Flow));
        }
        *window += added;
        Ok(())
    }

    pub fn grant(&mut self, stream: u32, increment: u32) -> Result<(), Misuse> {
        let added = i64::from(increment);
        let window = self.window(stream, false).ok_or(Misuse::Closed)?;
        if increment == 0 || *window + added > LIMIT {
            return Err(Misuse::Increment);
        }
        *window += added;
        Ok(())
    }

    pub fn local(&mut self, size: u32) -> Result<(), Fault> {
        let target = Self::size(size)?;
        let delta = target - self.ours;
        if self.streams.values().any(|pair| pair.inn + delta > LIMIT) {
            return Err(Fault::Connection { code: Code::Flow });
        }
        for pair in self.streams.values_mut() {
            pair.inn += delta;
        }
        self.ours = target;
        Ok(())
    }

    pub fn remote(&mut self, size: u32) -> Result<(), Fault> {
        let target = Self::size(size)?;
        let delta = target - self.theirs;
        if self.streams.values().any(|pair| pair.out + delta > LIMIT) {
            return Err(Fault::Connection { code: Code::Flow });
        }
        for pair in self.streams.values_mut() {
            pair.out += delta;
        }
        self.theirs = target;
        Ok(())
    }

    fn size(size: u32) -> Result<i64, Fault> {
        let value = i64::from(size);
        if value > LIMIT {
            return Err(Fault::Connection { code: Code::Flow });
        }
        Ok(value)
    }

    fn pair(&self, stream: u32) -> Option<Pair> {
        match stream {
            0 => Some(self.connection),
            _ => self.streams.get(&stream).copied(),
        }
    }

    fn window(&mut self, stream: u32, out: bool) -> Option<&mut i64> {
        let pair = match stream {
            0 => &mut self.connection,
            _ => self.streams.get_mut(&stream)?,
        };
        Some(if out { &mut pair.out } else { &mut pair.inn })
    }

    fn fault(stream: u32) -> impl Fn(Code) -> Fault {
        move |code| match stream {
            0 => Fault::Connection { code },
            _ => Fault::Stream { stream, code },
        }
    }
}
