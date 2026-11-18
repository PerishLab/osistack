#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Empty,
    Character,
    Padding,
    Range,
}
