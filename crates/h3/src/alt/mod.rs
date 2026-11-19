mod cache;
mod parse;
mod scan;

pub use cache::Cache;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn new(host: &str, port: u16) -> Origin {
        Origin {
            host: host.to_ascii_lowercase(),
            port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternative {
    pub protocol: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub age: u64,
    pub persist: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    Clear,
    Offer(Vec<Alternative>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    Empty,
    Large,
    Syntax,
    Escape,
    Host,
    Port,
    Age,
    Repeat,
}
