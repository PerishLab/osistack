use crate::error::Error;
use crate::exchange::Exchange;
use h1::{Field, Framing, Head, Request};
use http::{Method, Name, Scheme, Uri, Value};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub head: usize,
    pub body: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub head: Head,
    pub body: Vec<u8>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            write: Duration::from_secs(30),
            head: 64 * 1024,
            body: 16 * 1024 * 1024,
        }
    }
}

impl Client {
    pub fn fetch(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        if uri.scheme() != Scheme::Http {
            return Err(Error::Scheme);
        }
        let bodiless = method.text() == "HEAD";
        let fields = Self::fields(&method, uri, body)?;
        let request = Request::new(method, &uri.target(), fields)?.encode()?;
        let mut exchange = Exchange::open(self, uri.host(), uri.port())?;
        exchange.send(&request)?;
        exchange.send(body)?;
        let head = exchange.head()?;
        let framing = if bodiless {
            Framing::Empty
        } else {
            Framing::of(&head)?
        };
        let body = exchange.body(framing)?;
        Ok(Response { head, body })
    }

    fn fields(method: &Method, uri: &Uri, body: &[u8]) -> Result<Vec<Field>, Error> {
        let mut fields = vec![
            Self::field("host", uri.authority().as_bytes())?,
            Self::field("connection", b"close")?,
        ];
        if !body.is_empty() || !matches!(method.text(), "GET" | "HEAD") {
            let size = body.len().to_string();
            fields.push(Self::field("content-length", size.as_bytes())?);
        }
        Ok(fields)
    }

    fn field(name: &str, value: &[u8]) -> Result<Field, Error> {
        Ok(Field {
            name: Name::new(name)?,
            value: Value::new(value)?,
        })
    }
}
