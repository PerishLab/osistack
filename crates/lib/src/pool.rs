use crate::client::{Client, Response};
use crate::clock::Mux;
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
    mux: Option<Mux>,
}

struct Opened<'a> {
    exchange: Exchange<'a>,
    mux: Option<Mux>,
    reused: bool,
}

impl Pool {
    pub fn new(client: Client) -> Self {
        Self { client, held: None }
    }

    pub fn fetch(&mut self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
        if !matches!(uri.scheme(), Scheme::Http | Scheme::Https) {
            return Err(Error::Scheme);
        }
        let taken = self
            .held
            .take()
            .filter(|held| held.host == uri.host() && held.port == uri.port());
        let opened = match taken {
            Some(held) => Opened {
                exchange: Exchange::restore(
                    &self.client,
                    held.slot,
                    Instant::now() + self.client.total,
                ),
                mux: held.mux,
                reused: true,
            },
            None => Opened {
                exchange: Self::open(&self.client, uri)?,
                mux: None,
                reused: false,
            },
        };
        if opened.h2() {
            let (response, slot, mux) = opened.http2(&self.client, method, uri, body)?;
            self.held = Some(Held {
                slot,
                host: uri.host().to_owned(),
                port: uri.port(),
                mux: Some(mux),
            });
            Ok(response)
        } else {
            let (response, held) = opened.plain(&self.client, method, uri, body)?;
            self.held = held;
            Ok(response)
        }
    }

    fn open<'a>(client: &'a Client, uri: &Uri) -> Result<Exchange<'a>, Error> {
        let mut exchange = Exchange::open(client, uri.host(), uri.port())?;
        if uri.scheme() == Scheme::Https {
            exchange.wire(uri.host())?;
        }
        Ok(exchange)
    }
}

impl<'a> Opened<'a> {
    fn h2(&self) -> bool {
        self.exchange.h2()
    }

    fn plain(
        mut self,
        client: &'a Client,
        method: Method,
        uri: &Uri,
        body: &[u8],
    ) -> Result<(Response, Option<Held>), Error> {
        let bodiless = method.text() == "HEAD" || method.text() == "CONNECT";
        let fields = Client::fields(&method, uri, body, false)?;
        let request = Request::new(method, &uri.target(), fields)?.encode()?;
        if let Err(error) = self
            .exchange
            .send(&request)
            .and_then(|_| self.exchange.send(body))
        {
            if !self.reused {
                return Err(error);
            }
            self.exchange = Pool::open(client, uri)?;
            self.exchange.send(&request)?;
            self.exchange.send(body)?;
        }
        let head = self.exchange.head()?;
        let framing = if bodiless {
            Framing::Empty
        } else {
            Framing::of(&head)?
        };
        let body = self.exchange.body(framing)?;
        let held = kept(uri, &head, framing, self.exchange);
        Ok((Response { head, body }, held))
    }

    fn http2(
        mut self,
        client: &'a Client,
        method: Method,
        uri: &Uri,
        body: &[u8],
    ) -> Result<(Response, Slot, Mux), Error> {
        let mut live = match self.mux.take() {
            Some(mux) => mux,
            None => Mux::boot(&mut self.exchange)?,
        };
        let response = match live.ask(&mut self.exchange, method.clone(), uri, body) {
            Ok(response) => response,
            Err(_error) if self.reused => {
                self.exchange = Pool::open(client, uri)?;
                live = Mux::boot(&mut self.exchange)?;
                live.ask(&mut self.exchange, method, uri, body)?
            }
            Err(error) => return Err(error),
        };
        Ok((response, self.exchange.release(), live))
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
        mux: None,
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
