mod decode;
mod form;

use crate::error::Error;
use crate::field::{Name, Value};
use crate::method::Method;
use crate::uri::{Scheme, Uri};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub(super) method: Method,
    pub(super) scheme: Scheme,
    pub(super) authority: String,
    pub(super) path: String,
    pub(super) fields: Vec<(Name, Value)>,
}

pub(super) fn hopping(name: &Name) -> bool {
    matches!(
        name.text(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

fn located(authority: &str) -> Result<(), Error> {
    if authority.is_empty() || authority.contains('@') {
        Err(Error::Host)
    } else {
        Ok(())
    }
}

fn shaped(method: &Method, path: &str) -> Result<(), Error> {
    if method.text() == "CONNECT" {
        return if path.is_empty() {
            Ok(())
        } else {
            Err(Error::Target)
        };
    }
    if path == "*" {
        return if method.text() == "OPTIONS" {
            Ok(())
        } else {
            Err(Error::Target)
        };
    }
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(Error::Target)
    }
}

pub(super) fn make(request: Request) -> Result<Request, Error> {
    located(&request.authority)?;
    shaped(&request.method, &request.path)?;
    if request.fields.iter().any(|(name, _)| name.text() == "host") {
        Err(Error::Host)
    } else {
        Ok(request)
    }
}

impl Request {
    pub fn new(method: Method, uri: &Uri, fields: Vec<(Name, Value)>) -> Result<Self, Error> {
        let path = if method.text() == "CONNECT" {
            String::new()
        } else {
            uri.target()
        };
        make(Self {
            method,
            scheme: uri.scheme(),
            authority: uri.authority(),
            path,
            fields,
        })
    }

    pub fn star(uri: &Uri, fields: Vec<(Name, Value)>) -> Result<Self, Error> {
        make(Self {
            method: Method::new("OPTIONS")?,
            scheme: uri.scheme(),
            authority: uri.authority(),
            path: "*".into(),
            fields,
        })
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn fields(&self) -> &[(Name, Value)] {
        &self.fields
    }

    pub fn target(&self) -> String {
        if self.method.text() == "CONNECT" {
            self.authority.clone()
        } else if self.path == "*" {
            "*".into()
        } else {
            self.path.clone()
        }
    }

    pub fn written(&self) -> Result<Vec<(Name, Value)>, Error> {
        let host = Name::new("host")?;
        let value = Value::new(self.authority.as_bytes())?;
        let mut fields = vec![(host, value)];
        fields.extend(self.fields.iter().cloned());
        Ok(fields)
    }

    pub fn headers(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut lines = vec![
            (b":method".to_vec(), self.method.text().as_bytes().to_vec()),
            (b":scheme".to_vec(), self.scheme.text().as_bytes().to_vec()),
            (b":authority".to_vec(), self.authority.as_bytes().to_vec()),
        ];
        if self.method.text() != "CONNECT" {
            lines.push((b":path".to_vec(), self.path.as_bytes().to_vec()));
        }
        for (name, value) in &self.fields {
            if !hopping(name) {
                lines.push((name.text().as_bytes().to_vec(), value.bytes().to_vec()));
            }
        }
        lines
    }

    pub fn parse(method: Method, target: &str, fields: Vec<(Name, Value)>) -> Result<Self, Error> {
        form::parse(method, target, fields)
    }

    pub fn incoming(lines: &[(Vec<u8>, Vec<u8>)]) -> Result<Self, Error> {
        decode::run(lines)
    }
}
