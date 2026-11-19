use crate::fault::{Code, Fault};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Going(pub u64);

#[derive(Debug, Clone, Default)]
pub struct Streams {
    next: u64,
    open: BTreeSet<u64>,
    going: Option<u64>,
}

impl Streams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&mut self) -> Result<u64, Going> {
        if let Some(id) = self.going {
            return Err(Going(id));
        }
        let stream = self.next;
        self.next += 4;
        self.open.insert(stream);
        Ok(stream)
    }

    pub fn close(&mut self, stream: u64) -> bool {
        self.open.remove(&stream)
    }

    pub fn active(&self) -> Vec<u64> {
        self.open.iter().copied().collect()
    }

    pub fn going(&self) -> Option<u64> {
        self.going
    }

    pub fn goaway(&mut self, id: u64) -> Result<Vec<u64>, Fault> {
        let raised = self.going.is_some_and(|before| id > before);
        if !id.is_multiple_of(4) || raised {
            return Err(Fault::Connection { code: Code::Id });
        }
        self.going = Some(id);
        Ok(self.open.split_off(&id).into_iter().collect())
    }
}
