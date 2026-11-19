use crate::blocked::{Decoded, Waiting};
use crate::error::Error;
use crate::field::Field;
use crate::lines::Lines;
use crate::section::Section;
use crate::stream::Feedback;
use crate::stream::{Instruction, Name};
use crate::tables::{Dynamic, Table};
use wire::{Huffman, Reader};

#[derive(Debug, Clone)]
pub struct Decoder {
    capacity: usize,
    huffman: Huffman,
    table: Dynamic,
    limit: usize,
    known: u64,
    waiting: Vec<Waiting>,
}

impl Decoder {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            huffman: Huffman::new(),
            table: Dynamic::new(capacity),
            limit: 0,
            known: 0,
            waiting: Vec::new(),
        }
    }

    pub fn blocked(self, limit: usize) -> Self {
        Self { limit, ..self }
    }

    pub fn known(&self) -> u64 {
        self.known
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    pub fn table(&self) -> &Dynamic {
        &self.table
    }

    pub fn apply(&mut self, input: &[u8]) -> Result<usize, Error> {
        let mut used = 0;
        while let Some((instruction, size)) = Instruction::decode(&input[used..], &self.huffman)? {
            self.run(instruction)?;
            used += size;
        }
        Ok(used)
    }

    fn run(&mut self, instruction: Instruction) -> Result<(), Error> {
        match instruction {
            Instruction::Capacity(value) => {
                let value = usize::try_from(value).map_err(|_| Error::Capacity)?;
                self.table.resize(value)
            }
            Instruction::Duplicate(index) => {
                let field = self.past(index)?;
                self.table.insert(field).map(|_| ())
            }
            Instruction::Insert { name, value } => {
                let name = self.source(name)?;
                self.table.insert(Field::new(&name, &value)).map(|_| ())
            }
        }
    }

    fn past(&self, index: u64) -> Result<Field, Error> {
        let absolute = self.table.relative(index).ok_or(Error::Index)?;
        self.table.get(absolute).cloned().ok_or(Error::Index)
    }

    fn source(&self, name: Name) -> Result<Vec<u8>, Error> {
        match name {
            Name::Static(index) => Ok(Table::get(index).ok_or(Error::Index)?.name),
            Name::Dynamic(index) => Ok(self.past(index)?.name),
            Name::Literal(bytes) => Ok(bytes),
        }
    }

    pub fn decode(&self, block: &[u8]) -> Result<Vec<Field>, Error> {
        let mut reader = Reader::new(block);
        let section = Section::read(&mut reader, self.capacity, 0)?;
        if section.required > 0 {
            return Err(Error::Dynamic);
        }
        let lines = Lines::new(&self.huffman, &self.table, section);
        lines.all(&block[reader.at()..])
    }

    pub fn section(&mut self, stream: u64, block: &[u8]) -> Result<Option<Decoded>, Error> {
        let mut reader = Reader::new(block);
        let section = Section::read(&mut reader, self.capacity, self.table.inserted())?;
        let rest = block[reader.at()..].to_vec();
        if section.required <= self.table.inserted() {
            return self.finish(stream, section, &rest).map(Some);
        }
        if self.waiting.len() >= self.limit {
            return Err(Error::Blocked);
        }
        self.waiting.push(Waiting {
            stream,
            section,
            rest,
        });
        Ok(None)
    }

    pub fn ready(&mut self) -> Result<Vec<Decoded>, Error> {
        let inserted = self.table.inserted();
        let (go, keep) = std::mem::take(&mut self.waiting)
            .into_iter()
            .partition::<Vec<_>, _>(|waiting| waiting.section.required <= inserted);
        self.waiting = keep;
        go.iter()
            .map(|waiting| self.finish(waiting.stream, waiting.section, &waiting.rest))
            .collect()
    }

    pub fn cancel(&mut self, stream: u64) -> Feedback {
        self.waiting.retain(|waiting| waiting.stream != stream);
        Feedback::Cancel(stream)
    }

    pub fn increment(&mut self) -> Option<Feedback> {
        let delta = self.table.inserted().saturating_sub(self.known);
        self.known += delta;
        (delta > 0).then_some(Feedback::Increment(delta))
    }

    fn finish(&mut self, stream: u64, section: Section, rest: &[u8]) -> Result<Decoded, Error> {
        let lines = Lines::new(&self.huffman, &self.table, section);
        let fields = lines.all(rest)?;
        let feedback = (section.required > 0).then_some(Feedback::Acknowledge(stream));
        self.known = self.known.max(section.required);
        Ok(Decoded {
            stream,
            fields,
            feedback,
        })
    }
}
