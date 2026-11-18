use crate::error::Error;
use crate::line::find;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    pub data: Vec<u8>,
    pub used: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunked;

impl Chunked {
    pub fn encode(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut out = format!("{:x}\r\n", data.len()).into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        out
    }

    pub fn finish() -> Vec<u8> {
        b"0\r\n\r\n".to_vec()
    }

    pub fn decode(input: &[u8]) -> Result<Option<Body>, Error> {
        let mut data = Vec::new();
        let mut at = 0;
        loop {
            let Some(end) = find(&input[at..], b"\n").map(|found| at + found) else {
                return Ok(None);
            };
            let line = input[at..end].strip_suffix(b"\r").ok_or(Error::Chunk)?;
            let size = size(line)?;
            at = end + 1;
            if size == 0 {
                return last(input, at, data);
            }
            let stop = usize::try_from(size)
                .ok()
                .and_then(|length| at.checked_add(length))
                .ok_or(Error::Size)?;
            let Some(tail) = input
                .get(stop..stop.saturating_add(2))
                .filter(|tail| tail.len() == 2)
            else {
                return Ok(None);
            };
            if tail != b"\r\n" {
                return Err(Error::Chunk);
            }
            data.extend_from_slice(&input[at..stop]);
            at = stop + 2;
        }
    }
}

fn last(input: &[u8], at: usize, data: Vec<u8>) -> Result<Option<Body>, Error> {
    match input.get(at..) {
        Some([b'\r', b'\n', ..]) => Ok(Some(Body { data, used: at + 2 })),
        Some([b'\r']) | Some([]) | None => Ok(None),
        Some(_) => Err(Error::Trailer),
    }
}

fn size(line: &[u8]) -> Result<u64, Error> {
    let split = line
        .iter()
        .position(|byte| *byte == b';')
        .unwrap_or(line.len());
    let (digits, extension) = line.split_at(split);
    if extension
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(Error::Chunk);
    }
    if digits.is_empty() {
        return Err(Error::Chunk);
    }
    let mut total = 0u64;
    for byte in digits {
        let digit = (*byte as char).to_digit(16).ok_or(Error::Chunk)?;
        total = total
            .checked_mul(16)
            .and_then(|shifted| shifted.checked_add(digit as u64))
            .ok_or(Error::Size)?;
    }
    Ok(total)
}
