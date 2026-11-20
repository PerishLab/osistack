use super::keys::Keys;
use crate::error::Error;
use crate::packet::number::Number;
use crypto::Mask;

const LIMIT: u64 = 1 << 62;
const SAMPLE: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub number: u64,
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

fn nonce(iv: &[u8], number: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(iv);
    for (slot, byte) in out[4..].iter_mut().zip(number.to_be_bytes()) {
        *slot ^= byte;
    }
    out
}

fn bits(first: u8) -> u8 {
    if first & 0x80 != 0 { 0x0f } else { 0x1f }
}

impl Keys {
    fn mask(&self, packet: &[u8], offset: usize) -> Result<[u8; 5], Error> {
        let start = offset.checked_add(SAMPLE).ok_or(Error::Length)?;
        let tail = packet.get(start..).ok_or(Error::Length)?;
        let taken = tail.get(..16).ok_or(Error::Length)?;
        let sample: [u8; 16] = taken.try_into().map_err(|_| Error::Length)?;
        Ok(Mask::new(self.aead, &self.hp)?.mask(&sample))
    }

    pub fn protect(&self, number: u64, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let first = *header.first().ok_or(Error::Length)?;
        let length = usize::from(first & 3) + 1;
        let offset = header.len().checked_sub(length).filter(|at| *at > 0);
        let offset = offset.ok_or(Error::Length)?;
        let low = (number & ((1u64 << (8 * length)) - 1)).to_be_bytes();
        if number >= LIMIT || header[offset..] != low[8 - length..] {
            return Err(Error::Number);
        }
        let cipher = self.aead.cipher(&self.key)?;
        let mut data = payload.to_vec();
        let tag = cipher.seal(&nonce(&self.iv, number), header, &mut data)?;
        let mut packet = [header, &data, &tag].concat();
        let mask = self.mask(&packet, offset)?;
        packet[0] ^= mask[0] & bits(first);
        for (byte, with) in packet[offset..offset + length].iter_mut().zip(&mask[1..]) {
            *byte ^= with;
        }
        Ok(packet)
    }

    pub fn unprotect(
        &self,
        packet: &[u8],
        offset: usize,
        largest: Option<u64>,
    ) -> Result<Opened, Error> {
        if offset == 0 {
            return Err(Error::Length);
        }
        let mask = self.mask(packet, offset)?;
        let first = packet[0] ^ (mask[0] & bits(packet[0]));
        let length = usize::from(first & 3) + 1;
        let clear: Vec<u8> = packet[offset..offset + length]
            .iter()
            .zip(&mask[1..])
            .map(|(byte, with)| byte ^ with)
            .collect();
        let number = Number::read(first, &clear)?.restore(largest);
        let mut header = packet[..offset].to_vec();
        header[0] = first;
        header.extend_from_slice(&clear);
        let (body, tag) = packet[offset + length..].split_at(packet.len() - offset - length - 16);
        let mut payload = body.to_vec();
        let cipher = self.aead.cipher(&self.key)?;
        cipher.open(&nonce(&self.iv, number), &header, &mut payload, tag)?;
        Ok(Opened {
            number,
            header,
            payload,
        })
    }
}
