use crate::error::Error;
use crate::qpack::field::Field;
use crate::qpack::sending::pins::Pins;
use crate::qpack::stream::{Feedback, Instruction};
use crate::qpack::tables::Dynamic;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
struct Section {
    required: u64,
    cited: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct Tracker {
    table: Dynamic,
    known: u64,
    limit: usize,
    streams: BTreeMap<u64, Vec<Section>>,
    pins: Pins,
    draft: Vec<u64>,
}

impl Tracker {
    pub fn new(maximum: usize, blocked: usize) -> Self {
        Self {
            table: Dynamic::new(maximum),
            known: 0,
            limit: blocked,
            streams: BTreeMap::new(),
            pins: Pins::default(),
            draft: Vec::new(),
        }
    }

    pub fn table(&self) -> &Dynamic {
        &self.table
    }

    pub fn known(&self) -> u64 {
        self.known
    }

    pub fn blocked(&self) -> usize {
        self.streams
            .keys()
            .filter(|stream| self.stalled(**stream))
            .count()
    }

    pub fn outstanding(&self, stream: u64) -> usize {
        self.streams.get(&stream).map_or(0, Vec::len)
    }

    pub fn held(&self, absolute: u64) -> bool {
        self.pins.held(absolute)
    }

    pub fn admits(&self, stream: u64) -> bool {
        self.stalled(stream) || self.blocked() < self.limit
    }

    fn stalled(&self, stream: u64) -> bool {
        let known = self.known;
        self.streams
            .get(&stream)
            .is_some_and(|queue| queue.iter().any(|section| section.required > known))
    }

    pub fn apply(&mut self, instruction: &Instruction) -> Result<(), Error> {
        match instruction {
            Instruction::Capacity(value) => {
                let value = usize::try_from(*value).map_err(|_| Error::Capacity)?;
                if value > self.table.maximum() {
                    return Err(Error::Capacity);
                }
                self.safe(value, 0)?;
                self.table.resize(value)
            }
            Instruction::Duplicate(index) => {
                let absolute = self.table.relative(*index).ok_or(Error::Index)?;
                let field = self.table.get(absolute).cloned().ok_or(Error::Index)?;
                self.place(field)
            }
            Instruction::Insert { name, value } => {
                let name = self.table.origin(name)?;
                self.place(Field::new(&name, value))
            }
        }
    }

    fn place(&mut self, field: Field) -> Result<(), Error> {
        let cost = Dynamic::cost(&field);
        if cost > self.table.capacity() {
            return Err(Error::Oversize);
        }
        self.safe(self.table.capacity(), cost)?;
        self.table.insert(field).map(|_| ())
    }

    fn safe(&self, capacity: usize, extra: usize) -> Result<(), Error> {
        let count = self.table.evictions(capacity, extra);
        if self.pins.within(self.table.dropped(), count) {
            return Err(Error::Pinned);
        }
        Ok(())
    }

    pub fn cite(&mut self, absolute: u64) -> Result<(), Error> {
        self.table.get(absolute).ok_or(Error::Index)?;
        self.pins.hold(absolute);
        self.draft.push(absolute);
        Ok(())
    }

    pub fn abandon(&mut self) {
        for absolute in std::mem::take(&mut self.draft) {
            self.pins.release(absolute);
        }
    }

    pub fn sent(&mut self, stream: u64) -> Result<u64, Error> {
        let Some(top) = self.draft.iter().max().copied() else {
            return Ok(0);
        };
        let required = top + 1;
        let crowded = !self.stalled(stream) && self.blocked() >= self.limit;
        if required > self.known && crowded {
            self.abandon();
            return Err(Error::Blocked);
        }
        let cited = std::mem::take(&mut self.draft);
        let section = Section { required, cited };
        self.streams.entry(stream).or_default().push(section);
        Ok(required)
    }

    pub fn feedback(&mut self, feedback: Feedback) -> Result<(), Error> {
        match feedback {
            Feedback::Acknowledge(stream) => self.acknowledge(stream),
            Feedback::Cancel(stream) => {
                self.forget(stream);
                Ok(())
            }
            Feedback::Increment(count) => self.increase(count),
        }
    }

    pub fn receive(&mut self, input: &[u8]) -> Result<usize, Error> {
        let mut used = 0;
        while let Some((feedback, size)) = Feedback::decode(&input[used..])? {
            self.feedback(feedback)?;
            used += size;
        }
        Ok(used)
    }

    fn acknowledge(&mut self, stream: u64) -> Result<(), Error> {
        let queue = self
            .streams
            .get_mut(&stream)
            .filter(|queue| !queue.is_empty())
            .ok_or(Error::Feedback)?;
        let section = queue.remove(0);
        if queue.is_empty() {
            self.streams.remove(&stream);
        }
        for absolute in &section.cited {
            self.pins.release(*absolute);
        }
        self.known = self.known.max(section.required);
        Ok(())
    }

    fn forget(&mut self, stream: u64) {
        for section in self.streams.remove(&stream).into_iter().flatten() {
            for absolute in section.cited {
                self.pins.release(absolute);
            }
        }
    }

    fn increase(&mut self, count: u64) -> Result<(), Error> {
        if count == 0 {
            return Err(Error::Zero);
        }
        let total = self.known.checked_add(count).ok_or(Error::Feedback)?;
        if total > self.table.inserted() {
            return Err(Error::Feedback);
        }
        self.known = total;
        Ok(())
    }
}
