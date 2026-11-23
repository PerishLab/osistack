use std::fmt;

#[derive(Debug)]
pub enum Error {
    Socket(socket::Error),
    Frame(h1::Error),
    Http(http::Error),
    Tls(tls::Error),
    Http2(h2::Error),
    Scheme,
    Random,
    Limit,
    Short,
    Usage,
    Redirect,
    Timeout,
    Output,
    Status,
    Trust,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(error) => write!(out, "socket: {error}"),
            Self::Frame(error) => write!(out, "http/1.1 framing: {error}"),
            Self::Http(error) => write!(out, "http semantics: {error}"),
            Self::Tls(error) => write!(out, "tls: {error}"),
            Self::Http2(error) => write!(out, "http/2 framing: {error}"),
            Self::Scheme => write!(out, "only the http and https schemes are supported"),
            Self::Random => write!(out, "could not read random bytes"),
            Self::Limit => write!(out, "response exceeds the configured size limit"),
            Self::Short => write!(out, "connection closed before the response was complete"),
            Self::Usage => write!(out, "invalid fetch arguments"),
            Self::Redirect => write!(
                out,
                "redirect is missing, looped, or exceeded the hop limit"
            ),
            Self::Timeout => write!(out, "the request exceeded the total time limit"),
            Self::Output => write!(out, "could not write the output file"),
            Self::Status => write!(out, "the server returned an HTTP error status"),
            Self::Trust => write!(out, "https requires a trust root; pass --cacert FILE"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Http2(error) => Some(error),
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

impl From<tls::Error> for Error {
    fn from(error: tls::Error) -> Self {
        Self::Tls(error)
    }
}

impl From<h2::Error> for Error {
    fn from(error: h2::Error) -> Self {
        Self::Http2(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Output
    }
}
