use super::{Content, LIMIT, Record};
use crate::error::Error;
use crate::schedule::Keys;
use crypto::Aead;

const TAG: usize = 16;
const INNER: usize = 16384;
const HEADER: usize = 5;
const VERSION: u16 = 0x0303;

#[derive(Clone)]
pub struct Layer {
    aead: Aead,
    key: Vec<u8>,
    iv: [u8; 12],
    next: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub content: Content,
    pub payload: Vec<u8>,
}

fn nonce(iv: &[u8; 12], number: u64) -> [u8; 12] {
    let mut out = *iv;
    for (slot, byte) in out[4..].iter_mut().zip(number.to_be_bytes()) {
        *slot ^= byte;
    }
    out
}

fn header(version: u16, length: usize) -> Result<[u8; HEADER], Error> {
    let size = u16::try_from(length).map_err(|_| Error::Length)?;
    let mut out = [Content::Application.code(), 0, 0, 0, 0];
    out[1..3].copy_from_slice(&version.to_be_bytes());
    out[3..].copy_from_slice(&size.to_be_bytes());
    Ok(out)
}

fn allowed(content: Content, size: usize) -> Result<(), Error> {
    match content {
        Content::Change => Err(Error::Kind),
        Content::Handshake | Content::Alert if size == 0 => Err(Error::Kind),
        _ => Ok(()),
    }
}

impl Layer {
    pub fn new(aead: Aead, keys: &Keys) -> Result<Self, Error> {
        Self::at(aead, keys, 0)
    }

    pub fn at(aead: Aead, keys: &Keys, next: u64) -> Result<Self, Error> {
        let iv: [u8; 12] = keys.iv.as_slice().try_into().map_err(|_| Error::Length)?;
        if keys.key.len() != aead.key() {
            return Err(Error::Length);
        }
        Ok(Self {
            aead,
            key: keys.key.clone(),
            iv,
            next,
        })
    }

    pub fn protect(&mut self, content: Content, data: &[u8], pad: usize) -> Result<Record, Error> {
        allowed(content, data.len())?;
        if data.len() > INNER {
            return Err(Error::Length);
        }
        let next = self.next.checked_add(1).ok_or(Error::Length)?;
        let mut inner = Vec::new();
        inner.extend_from_slice(data);
        inner.push(content.code());
        inner.resize(inner.len().checked_add(pad).ok_or(Error::Length)?, 0);
        if inner.len() + TAG > LIMIT {
            return Err(Error::Length);
        }
        let aad = header(VERSION, inner.len() + TAG)?;
        let cipher = self.aead.cipher(&self.key)?;
        let tag = cipher.seal(&nonce(&self.iv, self.next), &aad, &mut inner)?;
        inner.extend_from_slice(&tag);
        self.next = next;
        Ok(Record {
            content: Content::Application,
            version: VERSION,
            fragment: inner,
        })
    }

    pub fn unprotect(&mut self, record: &Record) -> Result<Opened, Error> {
        if record.content != Content::Application {
            return Err(Error::Kind);
        }
        let length = record.fragment.len();
        if !(TAG + 1..=LIMIT).contains(&length) {
            return Err(Error::Length);
        }
        let next = self.next.checked_add(1).ok_or(Error::Length)?;
        let aad = header(record.version, length)?;
        let (body, tag) = record.fragment.split_at(length - TAG);
        let mut inner = body.to_vec();
        let cipher = self.aead.cipher(&self.key)?;
        cipher.open(&nonce(&self.iv, self.next), &aad, &mut inner, tag)?;
        let rest = inner
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or(Error::Length)?;
        let content = Content::of(inner[rest])?;
        let payload = inner[..rest].to_vec();
        allowed(content, payload.len())?;
        self.next = next;
        Ok(Opened { content, payload })
    }
}
