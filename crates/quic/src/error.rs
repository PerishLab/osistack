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
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}
