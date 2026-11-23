use crate::error::Error;
use crate::frame::{Framing, coding, length};
use crate::head::{Field, field, named};
use crate::line::{clean, find};
use http::{Method, Uri};

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
        shape(&method, target)?;
        Ok(Request {
            method,
            target: target.to_owned(),
            fields,
        })
    }

    pub fn parse(input: &[u8], limit: usize) -> Result<Option<(Request, usize)>, Error> {
        let end = find(input, b"\r\n\r\n").map(|at| at + 4);
        clean(&input[..end.unwrap_or(input.len())])?;
        let Some(end) = end else {
            return if input.len() > limit {
                Err(Error::Size)
            } else {
                Ok(None)
            };
        };
        if end > limit {
            return Err(Error::Size);
        }
        let text = &input[..end - 4];
        let split = find(text, b"\r\n").unwrap_or(text.len());
        let (method, target) = start(&text[..split])?;
        let mut fields = Vec::new();
        if split < text.len() {
            for line in text[split + 2..].split(|byte| *byte == b'\n') {
                fields.push(field(line.strip_suffix(b"\r").unwrap_or(line))?);
            }
        }
        Ok(Some((Request::new(method, &target, fields)?, end)))
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

fn start(line: &[u8]) -> Result<(Method, String), Error> {
    let mut parts = line.split(|byte| *byte == b' ');
    let method = parts.next().ok_or(Error::Line)?;
    let target = parts.next().ok_or(Error::Line)?;
    let version = parts.next().ok_or(Error::Line)?;
    if parts.next().is_some() {
        return Err(Error::Line);
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return if version.starts_with(b"HTTP/") {
            Err(Error::Version)
        } else {
            Err(Error::Line)
        };
    }
    let method = std::str::from_utf8(method).map_err(|_| Error::Line)?;
    let method = Method::new(method).map_err(|_| Error::Line)?;
    let target = std::str::from_utf8(target).map_err(|_| Error::Target)?;
    Ok((method, target.to_owned()))
}

fn shape(method: &Method, target: &str) -> Result<(), Error> {
    if method.text() == "CONNECT" {
        return if authority(target) {
            Ok(())
        } else {
            Err(Error::Target)
        };
    }
    if target == "*" {
        return if method.text() == "OPTIONS" {
            Ok(())
        } else {
            Err(Error::Target)
        };
    }
    if target.starts_with('/') || located(target) {
        return Ok(());
    }
    Err(Error::Target)
}

fn located(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        return false;
    }
    !target.contains('#') && Uri::parse(target).is_ok()
}

fn authority(target: &str) -> bool {
    if located(target) || target.starts_with('/') {
        return false;
    }
    let Ok(uri) = Uri::parse(&format!("http://{target}/")) else {
        return false;
    };
    if uri.target() != "/" {
        return false;
    }
    let tail = match target.split_once(']') {
        Some((_, tail)) if target.starts_with('[') => tail,
        _ => match target.rsplit_once(':') {
            Some((_, port)) => return numbered(port),
            None => return false,
        },
    };
    tail.strip_prefix(':').is_some_and(numbered)
}

fn numbered(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().ok().is_some_and(|port| port != 0)
}
