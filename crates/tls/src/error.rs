#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
    Kind,
    Length,
    Version,
    Suites,
    Compression,
    Duplicate,
    Trailing,
    Value,
    Missing,
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}

impl Error {
    pub fn inner(self) -> Self {
        match self {
            Error::Wire(_) => Error::Length,
            other => other,
        }
    }
}
