use crate::error::Error;
use crate::field::Field;
use std::collections::VecDeque;

const OVERHEAD: usize = 32;

#[derive(Debug, Clone)]
pub struct Dynamic {
    entries: VecDeque<Field>,
    maximum: usize,
    capacity: usize,
    size: usize,
    inserted: u64,
}

impl Dynamic {
    pub fn new(maximum: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            maximum,
            capacity: 0,
            size: 0,
            inserted: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn inserted(&self) -> u64 {
        self.inserted
    }

    pub fn dropped(&self) -> u64 {
        self.inserted - self.entries.len() as u64
    }

    pub fn get(&self, absolute: u64) -> Option<&Field> {
        let offset = absolute.checked_sub(self.dropped())?;
        self.entries.get(usize::try_from(offset).ok()?)
    }

    pub fn relative(&self, index: u64) -> Option<u64> {
        self.inserted.checked_sub(index)?.checked_sub(1)
    }

    pub fn entries(&self) -> Vec<Field> {
        self.entries.iter().cloned().collect()
    }

    pub fn resize(&mut self, capacity: usize) -> Result<(), Error> {
        if capacity > self.maximum {
            return Err(Error::Capacity);
        }
        self.capacity = capacity;
        self.evict(0);
        Ok(())
    }

    pub fn insert(&mut self, field: Field) -> Result<u64, Error> {
        let cost = Self::cost(&field);
        if cost > self.capacity {
            return Err(Error::Oversize);
        }
        self.evict(cost);
        self.size += cost;
        self.entries.push_back(field);
        self.inserted += 1;
        Ok(self.inserted - 1)
    }

    fn evict(&mut self, extra: usize) {
        while self.size + extra > self.capacity {
            let Some(oldest) = self.entries.pop_front() else {
                break;
            };
            self.size -= Self::cost(&oldest);
        }
    }

    fn cost(field: &Field) -> usize {
        field.name.len() + field.value.len() + OVERHEAD
    }
}
