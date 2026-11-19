use super::{GRANULARITY, INITIAL};
use crate::error::Error;
use std::collections::VecDeque;

pub const MINIMUM: u64 = 1200;
const LIMIT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Idle,
    Pending,
    Valid,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub token: [u8; 8],
    pub expand: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    state: Validity,
    sent: Vec<([u8; 8], bool)>,
    deadline: Option<u64>,
    timeout: u64,
    mtu: bool,
}

impl Path {
    pub fn new(current: u64) -> Self {
        let fresh = INITIAL + (INITIAL / 2 * 4).max(GRANULARITY);
        Self {
            state: Validity::Idle,
            sent: Vec::new(),
            deadline: None,
            timeout: current.max(fresh).saturating_mul(3),
            mtu: false,
        }
    }

    pub fn challenge(&mut self, now: u64, token: [u8; 8], room: u64) -> Result<Probe, Error> {
        if self.state == Validity::Failed {
            return Err(Error::Value);
        }
        if self.state != Validity::Pending {
            self.sent.clear();
            self.state = Validity::Pending;
            self.deadline = Some(now.saturating_add(self.timeout));
        }
        if self.sent.iter().any(|(held, _)| *held == token) {
            return Err(Error::Duplicate);
        }
        if self.sent.len() >= LIMIT {
            return Err(Error::Value);
        }
        let expand = room >= MINIMUM;
        self.sent.push((token, expand));
        Ok(Probe { token, expand })
    }

    pub fn response(&mut self, token: [u8; 8]) -> bool {
        if self.state != Validity::Pending {
            return false;
        }
        let Some((_, expanded)) = self.sent.iter().find(|(held, _)| *held == token) else {
            return false;
        };
        self.mtu |= *expanded;
        self.state = Validity::Valid;
        self.sent.clear();
        self.deadline = None;
        true
    }

    pub fn expire(&mut self, now: u64) -> bool {
        let due = self.deadline.is_some_and(|limit| now >= limit);
        if self.state == Validity::Pending && due {
            self.fail();
            return true;
        }
        false
    }

    pub fn abandon(&mut self) {
        if self.state == Validity::Pending {
            self.fail();
        }
    }

    fn fail(&mut self) {
        self.state = Validity::Failed;
        self.sent.clear();
        self.deadline = None;
    }

    pub fn validity(&self) -> Validity {
        self.state
    }

    pub fn mtu(&self) -> bool {
        self.mtu
    }

    pub fn deadline(&self) -> Option<u64> {
        self.deadline
    }

    pub fn timeout(&self) -> u64 {
        self.timeout
    }
}

#[derive(Debug, Clone, Default)]
pub struct Echo {
    queue: VecDeque<[u8; 8]>,
}

impl Echo {
    pub fn challenge(&mut self, token: [u8; 8]) -> bool {
        if self.queue.len() >= LIMIT {
            return false;
        }
        self.queue.push_back(token);
        true
    }

    pub fn next(&mut self, room: u64) -> Option<Probe> {
        if room == 0 {
            return None;
        }
        let token = self.queue.pop_front()?;
        Some(Probe {
            token,
            expand: room >= MINIMUM,
        })
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}
