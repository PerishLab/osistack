use crate::error::Error;
use crate::head::Head;
use crate::line::trim;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Empty,
    Length(u64),
    Chunked,
    Close,
}

impl Framing {
    pub fn of(head: &Head) -> Result<Framing, Error> {
        let code = head.status.get();
        if code < 200 || code == 204 || code == 304 {
            return Ok(Framing::Empty);
        }
        let encodings = head.values("transfer-encoding");
        let lengths = head.values("content-length");
        if encodings.is_empty() {
            return Ok(length(&lengths)?.map_or(Framing::Close, Framing::Length));
        }
        if !lengths.is_empty() {
            return Err(Error::Ambiguous);
        }
        coding(&encodings)
    }
}

pub fn items(values: &[&[u8]]) -> Vec<Vec<u8>> {
    let parts = values
        .iter()
        .flat_map(|value| value.split(|byte| *byte == b','));
    parts.map(|part| trim(part).to_ascii_lowercase()).collect()
}

pub fn length(values: &[&[u8]]) -> Result<Option<u64>, Error> {
    let mut found = None;
    for item in items(values) {
        let digits = !item.is_empty() && item.iter().all(u8::is_ascii_digit);
        let text = std::str::from_utf8(&item).map_err(|_| Error::Length)?;
        let number: u64 = text.parse().map_err(|_| Error::Length)?;
        if !digits || found.is_some_and(|prior| prior != number) {
            return Err(Error::Length);
        }
        found = Some(number);
    }
    Ok(found)
}

pub fn coding(values: &[&[u8]]) -> Result<Framing, Error> {
    let named: Vec<Vec<u8>> = items(values)
        .into_iter()
        .filter(|item| !item.is_empty())
        .collect();
    let Some((last, before)) = named.split_last() else {
        return Err(Error::Encoding);
    };
    if before.iter().any(|item| item == b"chunked") {
        return Err(Error::Encoding);
    }
    Ok(if last == b"chunked" {
        Framing::Chunked
    } else {
        Framing::Close
    })
}
