#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
    Index,
    Size,
    Length,
    Stream,
    Padding,
    Setting,
    Increment,
    Push,
    Kind,
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}
