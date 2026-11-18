use crate::error::Error;

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    pub fn at(&self) -> usize {
        self.at
    }

    pub fn left(&self) -> usize {
        self.data.len() - self.at
    }

    pub fn byte(&mut self) -> Result<u8, Error> {
        let taken = self.take(1)?;
        Ok(taken[0])
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.left() {
            return Err(Error::Truncated);
        }
        let start = self.at;
        self.at += count;
        Ok(&self.data[start..self.at])
    }
}

#[derive(Debug, Clone, Default)]
pub struct Writer {
    data: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn byte(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn put(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub fn written(&self) -> &[u8] {
        &self.data
    }

    pub fn finish(self) -> Vec<u8> {
        self.data
    }
}
