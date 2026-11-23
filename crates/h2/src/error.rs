use std::fmt;

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

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(error) => write!(out, "wire: {error}"),
            Error::Index => out.write_str("a header index is out of range"),
            Error::Size => out.write_str("the header table size is invalid"),
            Error::Length => out.write_str("a frame length is invalid"),
            Error::Stream => out.write_str("a stream identifier is invalid"),
            Error::Padding => out.write_str("frame padding is invalid"),
            Error::Setting => out.write_str("a settings value is invalid"),
            Error::Increment => out.write_str("a window increment is invalid"),
            Error::Push => out.write_str("server push is not allowed"),
            Error::Kind => out.write_str("the frame type is not recognized"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Wire(error) => Some(error),
            _ => None,
        }
    }
}
