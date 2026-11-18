use crate::error::Error;
use crate::frame::{Framing, coding, length};
use crate::head::{Field, named};
use http::Method;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub target: String,
    pub fields: Vec<Field>,
}

impl Request {
    pub fn new(method: Method, target: &str, fields: Vec<Field>) -> Result<Request, Error> {
        let visible = target.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
        if target.is_empty() || !visible {
            return Err(Error::Target);
        }
        Ok(Request {
            method,
            target: target.to_owned(),
            fields,
        })
    }

    pub fn framing(&self) -> Result<Framing, Error> {
        let encodings = named(&self.fields, "transfer-encoding");
        let lengths = named(&self.fields, "content-length");
        if encodings.is_empty() {
            return Ok(length(&lengths)?.map_or(Framing::Empty, Framing::Length));
        }
        if !lengths.is_empty() {
            return Err(Error::Ambiguous);
        }
        match coding(&encodings)? {
            Framing::Chunked => Ok(Framing::Chunked),
            _ => Err(Error::Encoding),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.framing()?;
        if named(&self.fields, "host").len() != 1 {
            return Err(Error::Host);
        }
        let mut out = Vec::new();
        out.extend_from_slice(self.method.text().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        let mut sized = false;
        for field in &self.fields {
            let repeat = field.name.text() == "content-length" && sized;
            sized |= field.name.text() == "content-length";
            if repeat {
                continue;
            }
            out.extend_from_slice(field.name.text().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(field.value.bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}
