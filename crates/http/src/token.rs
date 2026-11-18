use crate::error::Error;

pub fn valid(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

pub fn check(text: &str) -> Result<(), Error> {
    if text.is_empty() {
        return Err(Error::Empty);
    }
    if !text.bytes().all(valid) {
        return Err(Error::Character);
    }
    Ok(())
}
