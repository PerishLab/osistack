#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
    Index,
    Dynamic,
    Count,
    Base,
    Capacity,
    Oversize,
    Zero,
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}
