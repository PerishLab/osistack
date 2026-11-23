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
        self.chase(method, uri, body)
    }

    pub fn forward(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        self.issue(method, uri, body, &located(uri))
    }

    pub fn tunnel(&self, uri: &Uri) -> Result<Response, Error> {
        let method = Method::new("CONNECT")?;
        self.issue(method, uri, b"", &hostport(uri))
    }

    fn issue(
        &self,
        method: Method,
        uri: &Uri,
        body: &[u8],
        target: &str,
    ) -> Result<Response, Error> {
        if uri.scheme() != Scheme::Http {
            return Err(Error::Scheme);
        }
        let bodiless = method.text() == "HEAD" || method.text() == "CONNECT";
        let fields = Self::fields(&method, uri, body, true)?;
        let request = Request::new(method, target, fields)?.encode()?;
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

    pub(crate) fn fields(
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
        Ok(fields)
    }

    fn field(name: &str, value: &[u8]) -> Result<Field, Error> {
        Ok(Field {
            name: Name::new(name)?,
            value: Value::new(value)?,
        })
    }
    fn chase(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        let mut method = method;
        let mut target = uri.clone();
        let mut payload = body.to_vec();
        let mut seen = Vec::new();
        for hop in 0..=5 {
            let key = target.written();
            if seen.contains(&key) {
                return Err(Error::Redirect);
            }
            seen.push(key);
            let response = self.issue(method.clone(), &target, &payload, &target.target())?;
            let status = response.head.status.get();
            if !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            if hop == 5 {
                return Err(Error::Redirect);
            }
            let Some(next) = locate(&target, &response)? else {
                return Ok(response);
            };
            if next.scheme() != Scheme::Http {
                return Err(Error::Scheme);
            }
            if matches!(status, 301..=303) {
                method = Method::new("GET")?;
                payload.clear();
            }
            target = next;
        }
        Err(Error::Redirect)
    }
}

fn located(uri: &Uri) -> String {
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

fn locate(base: &Uri, response: &Response) -> Result<Option<Uri>, Error> {
    let Some(value) = response
        .head
        .fields
        .iter()
        .rfind(|field| field.name.text() == "location")
    else {
        return Ok(None);
    };
    let text = std::str::from_utf8(value.value.bytes()).map_err(|_| Error::Redirect)?;
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(base.join(text)?))
}
