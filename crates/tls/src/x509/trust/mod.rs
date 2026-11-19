mod host;
mod pem;
mod roots;

use super::Flaw;

pub use host::{Host, matches, verify};
pub use pem::{Block, blocks, decode};
pub use roots::Roots;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Host,
    Missing,
    Mismatch,
    Frame,
    Label,
    Base64,
    Certificate(Flaw),
}
