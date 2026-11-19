use super::Flaw;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oid(Vec<u8>);

fn subs(content: &[u8]) -> Result<Vec<u64>, Flaw> {
    if content.last().is_none_or(|last| last & 0x80 != 0) {
        return Err(Flaw::Value);
    }
    let mut out = Vec::new();
    let mut value = 0u64;
    let mut fresh = true;
    for byte in content {
        if fresh && *byte == 0x80 {
            return Err(Flaw::Minimal);
        }
        if value >> 57 != 0 {
            return Err(Flaw::Value);
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        fresh = byte & 0x80 == 0;
        if fresh {
            out.push(value);
            value = 0;
        }
    }
    Ok(out)
}

impl Oid {
    pub fn parse(content: &[u8]) -> Result<Self, Flaw> {
        subs(content)?;
        Ok(Self(content.to_vec()))
    }

    pub fn from(arcs: &[u64]) -> Self {
        let mut bytes = Vec::new();
        let first = arcs.first().copied().unwrap_or(0).min(2);
        let second = arcs.get(1).copied().unwrap_or(0);
        let head = first * 40 + second.min(u64::MAX / 2 - 80);
        let rest = arcs.get(2..).unwrap_or(&[]);
        for value in std::iter::once(&head).chain(rest) {
            let mut groups = vec![(value & 0x7f) as u8];
            let mut rest = value >> 7;
            while rest != 0 {
                groups.push((rest & 0x7f) as u8 | 0x80);
                rest >>= 7;
            }
            groups.reverse();
            bytes.extend(groups);
        }
        Self(bytes)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn arcs(&self) -> Vec<u64> {
        let all = subs(&self.0).unwrap_or_default();
        let Some((head, rest)) = all.split_first() else {
            return Vec::new();
        };
        let first = (*head / 40).min(2);
        let mut out = vec![first, *head - 40 * first];
        out.extend(rest);
        out
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: Vec<String> = self.arcs().iter().map(|arc| arc.to_string()).collect();
        write!(out, "{}", text.join("."))
    }
}
