use std::fmt;

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
    Blocked,
    Reference,
    Pinned,
    Feedback,
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
            Error::Index => out.write_str("a QPACK index is out of range"),
            Error::Dynamic => out.write_str("a QPACK dynamic table reference is not allowed"),
            Error::Count => out.write_str("a QPACK required insert count is invalid"),
            Error::Base => out.write_str("a QPACK base index is invalid"),
            Error::Capacity => out.write_str("the QPACK table capacity is invalid"),
            Error::Oversize => out.write_str("a QPACK field exceeds the size limit"),
            Error::Zero => out.write_str("a QPACK increment is zero"),
            Error::Blocked => out.write_str("a QPACK stream is blocked"),
            Error::Reference => out.write_str("a QPACK reference is invalid"),
            Error::Pinned => out.write_str("a QPACK entry is still referenced"),
            Error::Feedback => out.write_str("QPACK decoder feedback is invalid"),
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
