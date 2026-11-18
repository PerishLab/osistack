use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Informational,
    Success,
    Redirection,
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Status(u16);

impl Status {
    pub fn new(code: u16) -> Result<Self, Error> {
        if !(100..=599).contains(&code) {
            return Err(Error::Range);
        }
        Ok(Self(code))
    }

    pub fn get(self) -> u16 {
        self.0
    }

    pub fn class(self) -> Class {
        match self.0 / 100 {
            1 => Class::Informational,
            2 => Class::Success,
            3 => Class::Redirection,
            4 => Class::Client,
            _ => Class::Server,
        }
    }
}
