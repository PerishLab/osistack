use crate::error::Error;
use crate::table::{CODES, LENGTHS};

const EOS: usize = 256;
const LONGEST: usize = 30;

#[derive(Debug, Clone)]
pub struct Huffman {
    first: [u32; LONGEST + 1],
    count: [u32; LONGEST + 1],
    start: [usize; LONGEST + 1],
    order: Vec<u16>,
}

impl Default for Huffman {
    fn default() -> Self {
        Self::new()
    }
}

impl Huffman {
    pub fn new() -> Self {
        let mut order: Vec<u16> = (0..=EOS as u16).collect();
        order.sort_by_key(|symbol| (LENGTHS[*symbol as usize], *symbol));
        let mut count = [0u32; LONGEST + 1];
        for length in LENGTHS {
            count[length as usize] += 1;
        }
        let mut first = [0u32; LONGEST + 1];
        let mut start = [0usize; LONGEST + 1];
        for length in 1..=LONGEST {
            first[length] = (first[length - 1] + count[length - 1]) << 1;
            start[length] = start[length - 1] + count[length - 1] as usize;
        }
        Self {
            first,
            count,
            start,
            order,
        }
    }

    pub fn length(&self, symbol: u16) -> Option<u8> {
        LENGTHS.get(symbol as usize).copied()
    }

    pub fn size(&self, input: &[u8]) -> usize {
        let bits: usize = input
            .iter()
            .map(|byte| LENGTHS[*byte as usize] as usize)
            .sum();
        bits.div_ceil(8)
    }

    pub fn encode(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size(input));
        let mut accumulator = 0u64;
        let mut bits = 0u32;
        for byte in input {
            let length = LENGTHS[*byte as usize] as u32;
            accumulator = (accumulator << length) | CODES[*byte as usize] as u64;
            bits += length;
            while bits >= 8 {
                out.push((accumulator >> (bits - 8)) as u8);
                bits -= 8;
            }
            accumulator &= (1u64 << bits) - 1;
        }
        if bits > 0 {
            let spare = 8 - bits;
            out.push(((accumulator << spare) | ((1u64 << spare) - 1)) as u8);
        }
        out
    }

    pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(input.len() * 2);
        let mut code = 0u32;
        let mut length = 0usize;
        let stream = input
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1));
        for bit in stream {
            code = (code << 1) | bit as u32;
            length += 1;
            if let Some(symbol) = self.lookup(code, length) {
                if symbol == EOS {
                    return Err(Error::Symbol);
                }
                out.push(symbol as u8);
                code = 0;
                length = 0;
            }
        }
        if length > 7 || code != (1u32 << length) - 1 {
            return Err(Error::Padding);
        }
        Ok(out)
    }

    fn lookup(&self, code: u32, length: usize) -> Option<usize> {
        let first = *self.first.get(length)?;
        let delta = code.checked_sub(first)?;
        if delta >= self.count[length] {
            return None;
        }
        self.order
            .get(self.start[length] + delta as usize)
            .map(|symbol| *symbol as usize)
    }
}
