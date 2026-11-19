use crate::error::Error;
use crate::frame::Frame;

const SMALLEST: usize = 21;
const TOKEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Open,
    Closing,
    Draining,
    Closed,
}

#[derive(Debug, Clone)]
pub struct Life {
    mode: Mode,
    until: u64,
    frame: Option<Frame>,
    count: u64,
}

impl Default for Life {
    fn default() -> Self {
        Self {
            mode: Mode::Open,
            until: 0,
            frame: None,
            count: 0,
        }
    }
}

impl Life {
    pub fn close(&mut self, now: u64, pto: u64, frame: Frame) -> Result<(), Error> {
        let fit = matches!(frame, Frame::Transport { .. } | Frame::Application { .. });
        if !fit || self.mode != Mode::Open {
            return Err(Error::Value);
        }
        self.mode = Mode::Closing;
        self.until = now.saturating_add(pto.saturating_mul(3));
        self.frame = Some(frame);
        Ok(())
    }

    pub fn receive(&mut self) -> Option<&Frame> {
        if self.mode != Mode::Closing {
            return None;
        }
        self.count = self.count.saturating_add(1);
        if self.count.is_power_of_two() {
            return self.frame.as_ref();
        }
        None
    }

    pub fn peer(&mut self, now: u64, pto: u64) {
        match self.mode {
            Mode::Open => {
                self.until = now.saturating_add(pto.saturating_mul(3));
                self.mode = Mode::Draining;
            }
            Mode::Closing => self.mode = Mode::Draining,
            Mode::Draining | Mode::Closed => {}
        }
    }

    pub fn reset(&mut self, now: u64, pto: u64) {
        self.peer(now, pto);
    }

    pub fn idle(&mut self) {
        if self.mode == Mode::Open {
            self.mode = Mode::Closed;
        }
    }

    pub fn expire(&mut self, now: u64) -> bool {
        if self.deadline().is_some_and(|due| now >= due) {
            self.mode = Mode::Closed;
            return true;
        }
        false
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn deadline(&self) -> Option<u64> {
        matches!(self.mode, Mode::Closing | Mode::Draining).then_some(self.until)
    }

    pub fn frame(&self) -> Option<&Frame> {
        if self.mode == Mode::Closing {
            return self.frame.as_ref();
        }
        None
    }
}

pub fn stateless(datagram: &[u8], tokens: &[[u8; 16]]) -> bool {
    if datagram.len() < SMALLEST {
        return false;
    }
    let tail = &datagram[datagram.len() - TOKEN..];
    let mut found = 0u8;
    for token in tokens {
        let mut diff = 0u8;
        for (left, right) in tail.iter().zip(token.iter()) {
            diff |= left ^ right;
        }
        found |= u8::from(diff == 0);
    }
    found != 0
}
