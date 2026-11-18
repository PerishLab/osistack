use crate::header::Header;
use crate::statics::STATIC;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    Full(usize),
    Name(usize),
    Absent,
}

#[derive(Debug, Clone)]
pub struct Table {
    entries: VecDeque<Header>,
    size: usize,
    limit: usize,
}

impl Table {
    pub fn new(limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            limit,
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn entries(&self) -> Vec<Header> {
        self.entries.iter().cloned().collect()
    }

    pub fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        match index {
            0 => None,
            1..=61 => STATIC
                .get(index - 1)
                .map(|(name, value)| (name.as_bytes(), value.as_bytes())),
            _ => self
                .entries
                .get(index - 62)
                .map(|entry| (&entry.name[..], &entry.value[..])),
        }
    }

    pub fn add(&mut self, header: Header) {
        let size = header.size();
        if size > self.limit {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.evict(self.limit - size);
        self.size += size;
        self.entries.push_front(header);
    }

    pub fn resize(&mut self, limit: usize) {
        self.limit = limit;
        self.evict(limit);
    }

    pub fn find(&self, name: &[u8], value: &[u8]) -> Found {
        let count = 61 + self.entries.len();
        let at = |index: usize| {
            self.get(index)
                .map(|(known, other)| (known == name, other == value))
        };
        let mut first = None;
        for index in 1..=count {
            match at(index) {
                Some((true, true)) => return Found::Full(index),
                Some((true, false)) if first.is_none() => first = Some(index),
                _ => {}
            }
        }
        first.map_or(Found::Absent, Found::Name)
    }

    fn evict(&mut self, room: usize) {
        while self.size > room {
            let Some(old) = self.entries.pop_back() else {
                break;
            };
            self.size -= old.size();
        }
    }
}
