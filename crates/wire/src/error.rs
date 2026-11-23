use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Range,
    Symbol,
    Padding,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Error::Truncated => "input ended before the field was complete",
            Error::Range => "the integer is outside the representable range",
            Error::Symbol => "the bit pattern is not a Huffman symbol",
            Error::Padding => "Huffman padding is invalid",
        };
        out.write_str(text)
    }
}

impl std::error::Error for Error {}
