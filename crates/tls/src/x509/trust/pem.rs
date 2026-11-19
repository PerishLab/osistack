use super::Refusal;

const BEGIN: &str = "-----BEGIN ";
const END: &str = "-----END ";
const DASHES: &str = "-----";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub label: String,
    pub data: Vec<u8>,
}

type Open = Option<(String, String)>;

fn lines(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        let step = match bytes[at] {
            b'\n' => 1,
            b'\r' if bytes.get(at + 1) == Some(&b'\n') => 2,
            b'\r' => 1,
            _ => {
                at += 1;
                continue;
            }
        };
        out.push(&text[start..at]);
        at += step;
        start = at;
    }
    if start < bytes.len() {
        out.push(&text[start..]);
    }
    out
}

struct Line<'a>(&'a str);

impl<'a> Line<'a> {
    fn trim(&self) -> &'a str {
        self.0.trim_end_matches([' ', '\t'])
    }

    fn opening(&self) -> Option<&'a str> {
        self.trim().strip_prefix(BEGIN)?.strip_suffix(DASHES)
    }

    fn closing(&self) -> Option<&'a str> {
        self.trim().strip_prefix(END)?.strip_suffix(DASHES)
    }

    fn begin(&self) -> Result<Open, Refusal> {
        if self.closing().is_some() {
            return Err(Refusal::Frame);
        }
        let Some(name) = self.opening() else {
            return Ok(None);
        };
        if !label(name) {
            return Err(Refusal::Label);
        }
        Ok(Some((name.to_string(), String::new())))
    }
}

fn label(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    let sep = |ch: char| ch == ' ' || ch == '-';
    let plain = chars.iter().all(|ch| ('\u{20}'..='\u{7e}').contains(ch));
    let edges = chars.first().is_none_or(|ch| !sep(*ch)) && chars.last().is_none_or(|ch| !sep(*ch));
    let pairs = chars.windows(2).all(|two| !(sep(two[0]) && sep(two[1])));
    plain && edges && pairs
}

fn sextet(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn group(quad: &[u8], last: bool) -> Result<Vec<u8>, Refusal> {
    let pad = quad.iter().rev().take_while(|byte| **byte == b'=').count();
    if pad > 2 || (pad > 0 && !last) {
        return Err(Refusal::Base64);
    }
    let mut word = 0u32;
    for byte in &quad[..4 - pad] {
        word = (word << 6) | sextet(*byte).ok_or(Refusal::Base64)?;
    }
    word <<= 6 * pad as u32;
    let raw = word.to_be_bytes();
    let keep = 3 - pad;
    if raw[1 + keep..].iter().any(|byte| *byte != 0) {
        return Err(Refusal::Base64);
    }
    Ok(raw[1..1 + keep].to_vec())
}

pub fn decode(text: &str) -> Result<Vec<u8>, Refusal> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(Refusal::Base64);
    }
    let quads = bytes.len() / 4;
    let mut out = Vec::with_capacity(quads * 3);
    for (at, quad) in bytes.chunks(4).enumerate() {
        out.extend(group(quad, at + 1 == quads)?);
    }
    Ok(out)
}

fn step(out: &mut Vec<Block>, open: Open, text: &str) -> Result<Open, Refusal> {
    let line = Line(text);
    let Some((name, mut body)) = open else {
        return line.begin();
    };
    if let Some(found) = line.closing() {
        if found != name {
            return Err(Refusal::Label);
        }
        out.push(Block {
            label: name,
            data: decode(&body)?,
        });
        return Ok(None);
    }
    if line.opening().is_some() {
        return Err(Refusal::Frame);
    }
    let kept = line.trim();
    if kept.is_empty() && !body.is_empty() {
        return Err(Refusal::Base64);
    }
    body.push_str(kept);
    Ok(Some((name, body)))
}

pub fn blocks(text: &str) -> Result<Vec<Block>, Refusal> {
    let mut out = Vec::new();
    let mut open = None;
    for line in lines(text) {
        open = step(&mut out, open, line)?;
    }
    if open.is_some() {
        return Err(Refusal::Frame);
    }
    Ok(out)
}
