use crate::clock::Clock;
use crate::error::Error;
use h1::{Field, Head};
use http::{Method, Name, Scheme, Uri, Value};
use std::time::Duration;
use tls::x509::trust::Roots;

#[derive(Debug, Clone)]
pub struct Client {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub total: Duration,
    pub head: usize,
    pub body: usize,
    pub roots: Roots,
    pub extra: Vec<Field>,
    pub via: Option<Uri>,
    pub follow: bool,
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
            total: Duration::from_secs(60),
            head: 64 * 1024,
            body: 16 * 1024 * 1024,
            roots: Roots::default(),
            extra: Vec::new(),
            via: None,
            follow: true,
        }
    }
}

impl Client {
    pub fn fetch(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        Clock::new(self).chase(method, uri, body)
    }

    pub fn forward(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        if uri.scheme() != Scheme::Http {
            return Err(Error::Scheme);
        }
        Clock::new(self).issue(method, uri, body, &located(uri))
    }

    pub fn tunnel(&self, uri: &Uri) -> Result<Response, Error> {
        if uri.scheme() != Scheme::Http {
            return Err(Error::Scheme);
        }
        let method = Method::new("CONNECT")?;
        Clock::new(self).issue(method, uri, b"", &hostport(uri))
    }

    pub(crate) fn fields(
        &self,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        close: bool,
    ) -> Result<Vec<Field>, Error> {
        let host = if method.text() == "CONNECT" {
            hostport(uri)
        } else {
            uri.authority()
        };
        let token = if close { "close" } else { "keep-alive" };
        let mut fields = vec![
            Self::field("host", host.as_bytes())?,
            Self::field("connection", token.as_bytes())?,
        ];
        if !body.is_empty() || !matches!(method.text(), "GET" | "HEAD" | "CONNECT") {
            let size = body.len().to_string();
            fields.push(Self::field("content-length", size.as_bytes())?);
        }
        fields.extend(self.extra.iter().cloned());
        Ok(fields)
    }

    fn field(name: &str, value: &[u8]) -> Result<Field, Error> {
        Ok(Field {
            name: Name::new(name)?,
            value: Value::new(value)?,
        })
    }
}

pub(crate) fn located(uri: &Uri) -> String {
    format!(
        "{}://{}{}",
        uri.scheme().text(),
        uri.authority(),
        uri.target()
    )
}

fn hostport(uri: &Uri) -> String {
    let host = uri.host();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!("{host}:{}", uri.port())
}
