use super::allowance::Allowance;
use super::credit::Credit;
use crate::fault::Fault;
use crate::frame::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choked(pub u64);

#[derive(Debug, Clone)]
pub struct Lanes {
    role: Role,
    open: [Credit; 2],
    admit: [Allowance; 2],
}

fn slot(kind: Direction) -> usize {
    match kind {
        Direction::Bidi => 0,
        Direction::Uni => 1,
    }
}

fn kind(id: u64) -> Direction {
    match id & 2 {
        0 => Direction::Bidi,
        _ => Direction::Uni,
    }
}

fn code(bit: u64, kind: Direction, index: u64) -> u64 {
    let uni = match kind {
        Direction::Bidi => 0,
        Direction::Uni => 2,
    };
    index * 4 + uni + bit
}

impl Role {
    fn bit(self) -> u64 {
        match self {
            Role::Client => 0,
            Role::Server => 1,
        }
    }
}

impl Lanes {
    pub fn new(role: Role, open: [u64; 2], admit: [u64; 2]) -> Self {
        Self {
            role,
            open: open.map(Credit::new),
            admit: admit.map(|limit| Allowance::new(limit, Fault::Limit)),
        }
    }

    pub fn open(&mut self, kind: Direction) -> Result<u64, Choked> {
        let credit = &mut self.open[slot(kind)];
        if credit.take(1) == 0 {
            return Err(Choked(credit.limit()));
        }
        Ok(code(self.role.bit(), kind, credit.used() - 1))
    }

    pub fn admit(&mut self, id: u64) -> Result<Vec<u64>, Fault> {
        let (kind, index) = (kind(id), id >> 2);
        if id & 1 == self.role.bit() {
            let seen = index < self.open[slot(kind)].used();
            return match (kind, seen) {
                (Direction::Bidi, true) => Ok(Vec::new()),
                _ => Err(Fault::State),
            };
        }
        let lane = &mut self.admit[slot(kind)];
        let before = lane.highest();
        lane.accept(index + 1)?;
        Ok((before..=index).map(|n| code(id & 1, kind, n)).collect())
    }

    pub fn close(&mut self, id: u64) {
        if id & 1 != self.role.bit() {
            self.admit[slot(kind(id))].consume(1);
        }
    }

    pub fn grant(&mut self, kind: Direction) -> Option<u64> {
        self.admit[slot(kind)].grant()
    }

    pub fn raise(&mut self, kind: Direction, limit: u64) -> bool {
        self.open[slot(kind)].raise(limit)
    }

    pub fn stalled(&mut self, kind: Direction) -> Option<u64> {
        self.open[slot(kind)].stalled()
    }
}
