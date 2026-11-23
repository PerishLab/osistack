use crate::client::{Client, Response};
use crate::error::Error;
use crate::exchange::{Exchange, Slot};
use h1::{Framing, Head, Request, Version};
use http::{Method, Scheme, Uri};
use std::time::Instant;

pub struct Pool {
    client: Client,
    held: Option<Held>,
}

struct Held {
    slot: Slot,
    host: String,
    port: u16,
}

impl Pool {
    pub fn new(client: Client) -> Self {
        Self { client, held: None }
    }

    pub fn fetch(&mut self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        if !matches!(uri.scheme(), Scheme::Http | Scheme::Https) {
            return Err(Error::Scheme);
        }
        let bodiless = method.text() == "HEAD" || method.text() == "CONNECT";
        let fields = Client::fields(&method, uri, body, false)?;
        let request = Request::new(method, &uri.target(), fields)?.encode()?;
        let reused = self.same(uri);
        let mut exchange = self.take(uri)?;
        if let Err(error) = exchange.send(&request).and_then(|_| exchange.send(body)) {
            if !reused {
                return Err(error);
            }
            exchange = Self::open(&self.client, uri)?;
            exchange.send(&request)?;
            exchange.send(body)?;
        }
        let head = exchange.head()?;
        let framing = if bodiless {
            Framing::Empty
        } else {
            Framing::of(&head)?
        };
        let body = exchange.body(framing)?;
        self.held = kept(uri, &head, framing, exchange);
        Ok(Response { head, body })
    }

    fn same(&self, uri: &Uri) -> bool {
        self.held
            .as_ref()
            .is_some_and(|held| held.host == uri.host() && held.port == uri.port())
    }

    fn take(&mut self, uri: &Uri) -> Result<Exchange<'_>, Error> {
        if let Some(held) = self
            .held
            .take()
            .filter(|held| held.host == uri.host() && held.port == uri.port())
        {
            return Ok(Exchange::restore(
                &self.client,
                held.slot,
                Instant::now() + self.client.total,
            ));
        }
        Self::open(&self.client, uri)
    }

    fn open<'a>(client: &'a Client, uri: &Uri) -> Result<Exchange<'a>, Error> {
        let mut exchange = Exchange::open(client, uri.host(), uri.port())?;
        if uri.scheme() == Scheme::Https {
            exchange.wrap(uri.host())?;
        }
        Ok(exchange)
    }
}

fn kept(uri: &Uri, head: &Head, framing: Framing, exchange: Exchange<'_>) -> Option<Held> {
    if !reusable(head, framing) {
        return None;
    }
    Some(Held {
        slot: exchange.release(),
        host: uri.host().to_owned(),
        port: uri.port(),
    })
}

fn reusable(head: &Head, framing: Framing) -> bool {
    if matches!(framing, Framing::Close) {
        return false;
    }
    match token(head) {
        Some("close") => false,
        Some("keep-alive") => true,
        _ => matches!(head.version, Version::Http11),
    }
}

fn token(head: &Head) -> Option<&str> {
    let value = head
        .fields
        .iter()
        .rfind(|field| field.name.text() == "connection")?;
    let text = std::str::from_utf8(value.value.bytes())
        .ok()?
        .to_ascii_lowercase();
    if text.split(',').any(|part| part.trim() == "close") {
        Some("close")
    } else if text.split(',').any(|part| part.trim() == "keep-alive") {
        Some("keep-alive")
    } else {
        None
    }
}
