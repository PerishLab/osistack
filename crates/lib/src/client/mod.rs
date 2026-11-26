mod random;
mod store;

pub(crate) use random::entropy;
pub use store::{load, stored};

use crate::clock::Clock;
use crate::error::Error;
use h1::{Field, Head, Version};
use h3::{Cache, Origin};
use http::{Method, Name, Scheme, Uri, Value};
use std::sync::{Arc, Mutex};
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
    pub http3: Http3,
    pub alts: Arc<Mutex<Cache>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3 {
    Off,
    Prefer,
    Only,
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
            roots: store::stored(),
            extra: Vec::new(),
            via: None,
            follow: true,
            http3: Http3::Off,
            alts: Arc::new(Mutex::new(Cache::new(8))),
        }
    }
}

impl Response {
    pub(crate) fn listed(&self) -> String {
        let tag = match self.head.version {
            Version::Http11 => "HTTP/1.1",
            Version::Http10 => "HTTP/1.0",
        };
        let mut out = format!("{tag} {} {}\r\n", self.head.status.get(), self.head.reason);
        for field in &self.head.fields {
            out.push_str(field.name.text());
            out.push_str(": ");
            out.push_str(&String::from_utf8_lossy(field.value.bytes()));
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out
    }
}

impl Client {
    pub fn fetch(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        self.trusted(uri)?;
        Clock::new(self).chase(method, uri, body)
    }

    pub(crate) fn trusted(&self, uri: &Uri) -> Result<(), Error> {
        if uri.scheme() == Scheme::Https && self.roots.count() == 0 {
            Err(Error::Trust)
        } else {
            Ok(())
        }
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

    pub fn clear(&self) {
        if let Ok(mut cache) = self.alts.lock() {
            *cache = Cache::new(8);
        }
    }

    pub(crate) fn offered(&self, host: &str, port: u16) -> Option<(String, u16)> {
        let cache = self.alts.lock().ok()?;
        let found = cache.best(&Origin::new(host, port), micros())?;
        Some((found.host.clone(), found.port))
    }

    pub(crate) fn remember(&self, host: &str, port: u16, head: &Head) {
        let values = head.values("alt-svc");
        if values.is_empty() {
            return;
        }
        let Ok(mut cache) = self.alts.lock() else {
            return;
        };
        let origin = Origin::new(host, port);
        let now = micros();
        for value in values {
            if let Ok(text) = std::str::from_utf8(value) {
                let _ = cache.receive(&origin, text, now);
            }
        }
    }
}

fn micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|spent| spent.as_micros() as u64)
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::{Client, Http3};

    #[test]
    fn preference() {
        assert_eq!(Client::default().http3, Http3::Off);
        let prefer = Client {
            http3: Http3::Prefer,
            ..Client::default()
        };
        assert_eq!(prefer.http3, Http3::Prefer);
        let only = Client {
            http3: Http3::Only,
            ..Client::default()
        };
        assert_eq!(only.http3, Http3::Only);
        assert_ne!(Http3::Off, Http3::Only);
    }
}
