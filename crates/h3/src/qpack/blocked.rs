use crate::qpack::field::Field;
use crate::qpack::section::Section;
use crate::qpack::stream::Feedback;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub stream: u64,
    pub fields: Vec<Field>,
    pub feedback: Option<Feedback>,
}

#[derive(Debug, Clone)]
pub struct Waiting {
    pub stream: u64,
    pub section: Section,
    pub rest: Vec<u8>,
}
