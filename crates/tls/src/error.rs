use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Wire(wire::Error),
    Crypto(crypto::Error),
    Kind,
    Length,
    Version,
    Suites,
    Compression,
    Duplicate,
    Trailing,
    Value,
    Missing,
    Place,
}

impl From<wire::Error> for Error {
    fn from(error: wire::Error) -> Self {
        Error::Wire(error)
    }
}

impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        Error::Crypto(error)
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

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(error) => write!(out, "wire: {error}"),
            Error::Crypto(error) => write!(out, "crypto: {error}"),
            Error::Kind => out.write_str("the record or handshake type is not recognized"),
            Error::Length => out.write_str("a TLS field length is invalid"),
            Error::Version => out.write_str("the TLS version is not recognized"),
            Error::Suites => out.write_str("no cipher suite was agreed"),
            Error::Compression => out.write_str("the compression method is not recognized"),
            Error::Duplicate => out.write_str("a TLS extension is repeated"),
            Error::Trailing => out.write_str("unexpected trailing data is present"),
            Error::Value => out.write_str("a TLS field value is invalid"),
            Error::Missing => out.write_str("a required TLS extension is missing"),
            Error::Place => out.write_str("a TLS extension appeared in the wrong place"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Wire(error) => Some(error),
            Error::Crypto(error) => Some(error),
            _ => None,
        }
    }
}
