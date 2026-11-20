use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Length,
    Auth,
    Zero,
    Point,
    Scalar,
    Format,
    Key,
}

impl From<radicula::Error> for Error {
    fn from(error: radicula::Error) -> Self {
        match error {
            radicula::Error::Length => Error::Length,
            radicula::Error::Auth => Error::Auth,
            radicula::Error::Zero => Error::Zero,
            radicula::Error::Point => Error::Point,
            radicula::Error::Scalar => Error::Scalar,
            radicula::Error::Format => Error::Format,
            radicula::Error::Key => Error::Key,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Error::Unsupported => "the primitive does not offer this combination",
            Error::Length => "length outside the range the construction defines",
            Error::Auth => "authentication failed",
            Error::Zero => "shared secret is all zero",
            Error::Point => "point is not a valid public key",
            Error::Scalar => "scalar outside the range the construction defines",
            Error::Format => "encoding is malformed",
            Error::Key => "public key is outside the range the construction defines",
        };
        out.write_str(text)
    }
}

impl std::error::Error for Error {}
