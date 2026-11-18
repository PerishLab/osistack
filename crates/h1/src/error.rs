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
}
