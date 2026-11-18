use crate::error::Error;
use crate::token;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Method(String);

impl Method {
    pub fn new(text: &str) -> Result<Self, Error> {
        token::check(text)?;
        Ok(Self(text.to_owned()))
    }

    pub fn text(&self) -> &str {
        &self.0
    }
}
