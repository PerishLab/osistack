use crate::error::Error;
use crate::field::{Name, Value};
use crate::status::Status;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: Status,
    fields: Vec<(Name, Value)>,
}

fn hopping(name: &Name) -> bool {
    matches!(
        name.text(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

impl Response {
    pub fn new(status: Status, fields: Vec<(Name, Value)>) -> Result<Self, Error> {
        Ok(Self { status, fields })
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn fields(&self) -> &[(Name, Value)] {
        &self.fields
    }

    pub fn headers(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let code = self.status.get().to_string();
        let mut lines = vec![(b":status".to_vec(), code.into_bytes())];
        for (name, value) in &self.fields {
            if !hopping(name) {
                lines.push((name.text().as_bytes().to_vec(), value.bytes().to_vec()));
            }
        }
        lines
    }

    pub fn incoming(lines: &[(Vec<u8>, Vec<u8>)]) -> Result<Self, Error> {
        let mut status = None;
        let mut fields = Vec::new();
        let mut body = false;
        for (name, value) in lines {
            if name.starts_with(b":") {
                if body {
                    return Err(Error::Order);
                }
                if name != b":status" {
                    return Err(Error::Pseudo);
                }
                if status.is_some() {
                    return Err(Error::Duplicate);
                }
                status = Some(coded(value)?);
            } else {
                body = true;
                if status.is_none() {
                    return Err(Error::Order);
                }
                let text = std::str::from_utf8(name).map_err(|_| Error::Character)?;
                fields.push((Name::new(text)?, Value::new(value)?));
            }
        }
        let status = status.ok_or(Error::Pseudo)?;
        Self::new(status, fields)
    }
}

fn coded(value: &[u8]) -> Result<Status, Error> {
    let text = std::str::from_utf8(value).map_err(|_| Error::Character)?;
    let code = text.parse::<u16>().map_err(|_| Error::Range)?;
    Status::new(code)
}
