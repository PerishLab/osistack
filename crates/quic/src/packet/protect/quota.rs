use crate::error::Error;
use crypto::Aead;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    used: u64,
    cap: u64,
}

impl Quota {
    pub fn confidential(aead: Aead) -> Self {
        let cap = match aead {
            Aead::Chacha => 1 << 62,
            Aead::Aes128 | Aead::Aes256 => 1 << 23,
        };
        Self { used: 0, cap }
    }

    pub fn integrity(aead: Aead) -> Self {
        let cap = match aead {
            Aead::Chacha => 1 << 36,
            Aead::Aes128 | Aead::Aes256 => 1 << 52,
        };
        Self { used: 0, cap }
    }

    pub const fn cap(self) -> u64 {
        self.cap
    }

    pub const fn used(self) -> u64 {
        self.used
    }

    pub const fn at(self, used: u64) -> Self {
        Self {
            used,
            cap: self.cap,
        }
    }

    pub fn consume(&mut self) -> Result<(), Error> {
        if self.used >= self.cap {
            return Err(Error::Limit);
        }
        self.used = self.used.checked_add(1).ok_or(Error::Limit)?;
        Ok(())
    }
}
