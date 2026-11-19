use super::table::Table;
use crate::error::Error;
use crate::qpack::field::Field;
use crate::qpack::stream::Name;
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

    pub fn maximum(&self) -> usize {
        self.maximum
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

    pub fn origin(&self, name: &Name) -> Result<Vec<u8>, Error> {
        match name {
            Name::Static(index) => Ok(Table::get(*index).ok_or(Error::Index)?.name),
            Name::Dynamic(index) => {
                let absolute = self.relative(*index).ok_or(Error::Index)?;
                Ok(self.get(absolute).ok_or(Error::Index)?.name.clone())
            }
            Name::Literal(bytes) => Ok(bytes.clone()),
        }
    }

    pub fn evictions(&self, capacity: usize, extra: usize) -> u64 {
        let mut size = self.size;
        let mut count = 0;
        for entry in &self.entries {
            if size + extra <= capacity {
                break;
            }
            size -= Self::cost(entry);
            count += 1;
        }
        count
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

    pub fn cost(field: &Field) -> usize {
        field.name.len() + field.value.len() + OVERHEAD
    }
}
