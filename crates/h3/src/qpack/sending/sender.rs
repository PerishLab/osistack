use crate::error::Error;
use crate::qpack::encoder::Encoder;
use crate::qpack::field::Field;
use crate::qpack::sending::tracker::Tracker;
use crate::qpack::stream::{Instruction, Name};
use crate::qpack::tables::{Dynamic, Found, Table};
use wire::Huffman;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    pub block: Vec<u8>,
    pub instructions: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Sender {
    encoder: Encoder,
    tracker: Tracker,
    huffman: Option<Huffman>,
}

impl Sender {
    pub fn new(maximum: usize, blocked: usize, huffman: bool) -> Self {
        Self {
            encoder: Encoder::new(huffman),
            tracker: Tracker::new(maximum, blocked),
            huffman: huffman.then(Huffman::new),
        }
    }

    pub fn tracker(&self) -> &Tracker {
        &self.tracker
    }

    pub fn capacity(&mut self, value: usize) -> Result<Vec<u8>, Error> {
        let instruction = Instruction::Capacity(value as u64);
        self.tracker.apply(&instruction)?;
        instruction.encode(self.huffman.as_ref())
    }

    pub fn encode(&mut self, stream: u64, fields: &[Field]) -> Result<Encoded, Error> {
        let mut instructions = Vec::new();
        for field in fields {
            instructions.extend(self.insert(field)?);
        }
        let table = self.tracker.table();
        let known = self.tracker.known();
        let reach = known + (table.maximum() / 32) as u64;
        let bound = if self.tracker.admits(stream) {
            reach
        } else {
            known
        };
        let (block, cited) = self
            .encoder
            .trace((table, table.inserted(), bound), fields)?;
        for absolute in cited {
            self.tracker.cite(absolute)?;
        }
        self.tracker.sent(stream)?;
        Ok(Encoded {
            block,
            instructions,
        })
    }

    pub fn receive(&mut self, input: &[u8]) -> Result<usize, Error> {
        self.tracker.receive(input)
    }

    fn insert(&mut self, field: &Field) -> Result<Vec<u8>, Error> {
        if field.sensitive || self.present(field) {
            return Ok(Vec::new());
        }
        let instruction = Instruction::Insert {
            name: self.source(field),
            value: field.value.clone(),
        };
        match self.tracker.apply(&instruction) {
            Ok(()) => instruction.encode(self.huffman.as_ref()),
            Err(Error::Pinned | Error::Oversize) => Ok(Vec::new()),
            Err(other) => Err(other),
        }
    }

    fn present(&self, field: &Field) -> bool {
        if let Found::Full(_) = Table::find(field) {
            return true;
        }
        let table = self.tracker.table();
        (table.dropped()..table.inserted()).any(|absolute| {
            let entry = table.get(absolute);
            entry.is_some_and(|line| line.name == field.name && line.value == field.value)
        })
    }

    fn source(&self, field: &Field) -> Name {
        if let Found::Full(index) | Found::Name(index) = Table::find(field) {
            return Name::Static(index);
        }
        let table = self.tracker.table();
        let doomed = table.evictions(table.capacity(), Dynamic::cost(field));
        let oldest = table.dropped() + doomed;
        let named = (oldest..table.inserted()).rev().find(|absolute| {
            let entry = table.get(*absolute);
            entry.is_some_and(|line| line.name == field.name)
        });
        match named {
            Some(absolute) => Name::Dynamic(table.inserted() - 1 - absolute),
            None => Name::Literal(field.name.clone()),
        }
    }
}
