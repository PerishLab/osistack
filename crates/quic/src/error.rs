use std::fmt;

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
    Limit,
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

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(error) => write!(out, "wire: {error}"),
            Error::Crypto(error) => write!(out, "crypto: {error}"),
            Error::Fixed => out.write_str("a fixed bit is incorrect"),
            Error::Reserved => out.write_str("a reserved bit is incorrect"),
            Error::Version => out.write_str("the QUIC version is not recognized"),
            Error::Length => out.write_str("a QUIC field length is invalid"),
            Error::Excluded => out.write_str("the frame type is excluded"),
            Error::Token => out.write_str("a retry token is invalid"),
            Error::Number => out.write_str("a packet number is invalid"),
            Error::Versions => out.write_str("the version negotiation list is invalid"),
            Error::Kind => out.write_str("the packet or frame type is not recognized"),
            Error::Minimal => out.write_str("the encoding is not the shortest form"),
            Error::Value => out.write_str("a QUIC field value is invalid"),
            Error::Empty => out.write_str("a required QUIC field is empty"),
            Error::Duplicate => out.write_str("a transport parameter is repeated"),
            Error::Limit => out.write_str("a QUIC limit is exceeded"),
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
