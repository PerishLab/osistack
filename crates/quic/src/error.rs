#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
    Crypto(crypto::Error),
    Fixed,
    Reserved,
    Version,
    Length,
    Excluded,
    Token,
    Number,
    Versions,
    Kind,
    Minimal,
    Value,
    Empty,
    Duplicate,
}

impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        Error::Crypto(error)
    }
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}
