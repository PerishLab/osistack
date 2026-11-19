#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
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

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}
