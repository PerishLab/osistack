use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Empty,
    Character,
    Padding,
    Range,
    Scheme,
    Userinfo,
    Host,
    Port,
    Order,
    Duplicate,
    Pseudo,
    Target,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Error::Empty => "the value is empty",
            Error::Character => "the value contains a disallowed character",
            Error::Padding => "the value has disallowed padding",
            Error::Range => "the value is outside the allowed range",
            Error::Scheme => "the URI scheme is missing or unsupported",
            Error::Userinfo => "the URI must not carry userinfo",
            Error::Host => "the URI host is missing or invalid",
            Error::Port => "the URI port is invalid",
            Error::Order => "a field appears out of order",
            Error::Duplicate => "a field is repeated",
            Error::Pseudo => "a pseudo-field is missing or invalid",
            Error::Target => "the request target is invalid",
        };
        out.write_str(text)
    }
}

impl std::error::Error for Error {}
