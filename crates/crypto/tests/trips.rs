use crypto::{Aead, Error};

struct Dice(u64);

impl Dice {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn bytes(&mut self, limit: usize) -> Vec<u8> {
        let count = self.below(limit);
        (0..count).map(|_| self.next() as u8).collect()
    }

    fn fill(&mut self, want: usize) -> Vec<u8> {
        (0..want).map(|_| self.next() as u8).collect()
    }

    fn nonce(&mut self) -> [u8; 12] {
        let bytes = self.fill(12);
        bytes.try_into().unwrap()
    }

    fn choice(&mut self) -> (Aead, usize) {
        [(Aead::Aes128, 16), (Aead::Aes256, 32), (Aead::Chacha, 32)][self.below(3)]
    }
}

#[test]
fn sealed() {
    let mut dice = Dice::new(31);
    for _ in 0..240 {
        let (aead, size) = dice.choice();
        let cipher = aead.cipher(&dice.fill(size)).unwrap();
        let nonce = dice.nonce();
        let aad = dice.bytes(48);
        let plain = dice.bytes(96);
        let mut data = plain.clone();
        let tag = cipher.seal(&nonce, &aad, &mut data).unwrap();
        assert_eq!(tag.len(), 16);
        cipher.open(&nonce, &aad, &mut data, &tag).unwrap();
        assert_eq!(data, plain, "{aead:?}");
    }
}

#[test]
fn spoiled() {
    let mut dice = Dice::new(37);
    for _ in 0..240 {
        let (aead, size) = dice.choice();
        let cipher = aead.cipher(&dice.fill(size)).unwrap();
        let nonce = dice.nonce();
        let aad = dice.bytes(48);
        let mut data = dice.bytes(96);
        if data.is_empty() {
            data = vec![dice.next() as u8];
        }
        let tag = cipher.seal(&nonce, &aad, &mut data).unwrap();
        let open = |data: &[u8], tag: &[u8]| {
            let mut copy = data.to_vec();
            cipher.open(&nonce, &aad, &mut copy, tag)
        };
        let mut flipped = data.clone();
        let at = dice.below(flipped.len());
        flipped[at] ^= 1;
        assert_eq!(open(&flipped, &tag), Err(Error::Auth), "{aead:?}");
        let mut broken = tag;
        broken[dice.below(16)] ^= 1;
        assert_eq!(open(&data, &broken), Err(Error::Auth), "{aead:?}");
        assert_eq!(open(&data, &tag[..15]), Err(Error::Length), "{aead:?}");
        assert_eq!(open(&data, &tag[..0]), Err(Error::Length), "{aead:?}");
        let cut = &data[..data.len() - 1];
        assert_eq!(open(cut, &tag), Err(Error::Auth), "{aead:?}");
    }
}
