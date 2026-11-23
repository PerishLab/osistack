use std::fmt;

#[derive(Debug)]
pub enum Error {
    Socket(socket::Error),
    Frame(h1::Error),
    Http(http::Error),
    Scheme,
    Limit,
    Short,
    Usage,
    Redirect,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(error) => write!(out, "socket: {error}"),
            Self::Frame(error) => write!(out, "http/1.1 framing: {error:?}"),
            Self::Http(error) => write!(out, "http semantics: {error:?}"),
            Self::Scheme => write!(out, "only the http scheme is supported"),
            Self::Limit => write!(out, "response exceeds the configured size limit"),
            Self::Short => write!(out, "connection closed before the response was complete"),
            Self::Usage => write!(out, "invalid fetch arguments"),
            Self::Redirect => write!(
                out,
                "redirect is missing, looped, or exceeded the hop limit"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) => Some(error),
            _ => None,
        }
    }
}

impl From<socket::Error> for Error {
    fn from(error: socket::Error) -> Self {
        Self::Socket(error)
    }
}

impl From<h1::Error> for Error {
    fn from(error: h1::Error) -> Self {
        Self::Frame(error)
    }
}

impl From<http::Error> for Error {
    fn from(error: http::Error) -> Self {
        Self::Http(error)
    }
}
