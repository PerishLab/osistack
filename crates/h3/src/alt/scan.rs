use super::Defect;

pub fn tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

pub fn elements(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (at, byte) in text.bytes().enumerate() {
        match (quoted, escaped, byte) {
            (true, true, _) => escaped = false,
            (true, false, b'\\') => escaped = true,
            (_, false, b'"') => quoted = !quoted,
            (false, _, b',') => {
                out.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    out.push(&text[start..]);
    out
}

pub struct Scan<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Scan<'a> {
    pub fn new(text: &'a str) -> Scan<'a> {
        Scan {
            bytes: text.as_bytes(),
            at: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn take(&mut self) -> Result<u8, Defect> {
        let byte = self.peek().ok_or(Defect::Syntax)?;
        self.at += 1;
        Ok(byte)
    }

    pub fn blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    pub fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        self.at += usize::from(found);
        found
    }

    pub fn token(&mut self) -> &'a [u8] {
        let start = self.at;
        while self.peek().is_some_and(tchar) {
            self.at += 1;
        }
        &self.bytes[start..self.at]
    }

    pub fn quoted(&mut self) -> Result<Vec<u8>, Defect> {
        if !self.eat(b'"') {
            return Err(Defect::Syntax);
        }
        let mut out = Vec::new();
        loop {
            let byte = self.take()?;
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.take()?),
                _ => out.push(byte),
            }
        }
    }

    pub fn value(&mut self) -> Result<Vec<u8>, Defect> {
        if self.peek() == Some(b'"') {
            return self.quoted();
        }
        let found = self.token();
        if found.is_empty() {
            return Err(Defect::Syntax);
        }
        Ok(found.to_vec())
    }
}
