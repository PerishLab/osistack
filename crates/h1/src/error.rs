use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Size,
    Line,
    Version,
    Status,
    Space,
    Fold,
    Field,
    Length,
    Ambiguous,
    Encoding,
    Chunk,
    Trailer,
    Target,
    Host,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Error::Size => "the header block exceeds the configured size limit",
            Error::Line => "a request or status line is malformed",
            Error::Version => "the HTTP version is not recognized",
            Error::Status => "the status code is not recognized",
            Error::Space => "a required space is missing",
            Error::Fold => "obsolete line folding is present",
            Error::Field => "a header field is malformed",
            Error::Length => "content-length is missing or invalid",
            Error::Ambiguous => "content length is ambiguous",
            Error::Encoding => "transfer-encoding is invalid",
            Error::Chunk => "a chunked body is malformed",
            Error::Trailer => "a trailer section is invalid",
            Error::Target => "the request target is invalid",
            Error::Host => "the host header is missing or invalid",
        };
        out.write_str(text)
    }
}

impl std::error::Error for Error {}
