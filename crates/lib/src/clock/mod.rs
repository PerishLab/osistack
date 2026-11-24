use crate::client::{Client, Response, located};
use crate::error::Error;
use crate::exchange::Exchange;
use h1::{Field, Framing, Head, Request, Version};
use h2::{Connection, Frame, Header, Settings};
use http::{Method, Name, Scheme, Status, Uri, Value};
use std::time::Instant;

mod handshake;
mod http3;

pub struct Clock<'a> {
    pub(crate) client: &'a Client,
    pub(crate) deadline: Instant,
}

impl<'a> Clock<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self {
            client,
            deadline: Instant::now() + client.total,
        }
    }

    pub fn issue(
        &self,
        method: Method,
        uri: &Uri,
        body: &[u8],
        target: &str,
    ) -> Result<Response, Error> {
        if !matches!(uri.scheme(), Scheme::Http | Scheme::Https) {
            return Err(Error::Scheme);
        }
        if uri.scheme() == Scheme::Https
            && let Some(response) = http3::first(self, method.clone(), uri, body)?
        {
            return Ok(response);
        }
        let bodiless = method.text() == "HEAD" || method.text() == "CONNECT";
        let hop = if uri.scheme() == Scheme::Http {
            self.client.via.as_ref().unwrap_or(uri)
        } else {
            uri
        };
        let mut exchange = Exchange::until(self.client, hop.host(), hop.port(), self.deadline)?;
        if uri.scheme() == Scheme::Https {
            exchange.wire(uri.host())?;
        }
        if exchange.h2() {
            return Mux::boot(&mut exchange)?.ask(&mut exchange, method, uri, body);
        }
        let fields = self.client.fields(&method, uri, body, true)?;
        let request = Request::new(method, target, fields)?.encode()?;
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

    pub fn chase(&self, method: Method, uri: &Uri, body: &[u8]) -> Result<Response, Error> {
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
            let line = if self.client.via.is_some() && target.scheme() == Scheme::Http {
                located(&target)
            } else {
                target.target().to_owned()
            };
            let response = self.issue(method.clone(), &target, &payload, &line)?;
            let status = response.head.status.get();
            if !self.client.follow || !matches!(status, 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            if hop == 5 {
                return Err(Error::Redirect);
            }
            let Some(next) = locate(&target, &response)? else {
                return Ok(response);
            };
            if !matches!(next.scheme(), Scheme::Http | Scheme::Https) {
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

fn asked(method: &Method, uri: &Uri, body: &[u8], extra: &[Field]) -> Vec<Header> {
    let mut fields = vec![
        Header::new(b":method", method.text().as_bytes()),
        Header::new(b":scheme", uri.scheme().text().as_bytes()),
        Header::new(b":authority", uri.authority().as_bytes()),
        Header::new(b":path", uri.target().as_bytes()),
    ];
    if !body.is_empty() {
        let size = body.len().to_string();
        fields.push(Header::new(b"content-length", size.as_bytes()));
    }
    for field in extra {
        fields.push(Header::new(
            field.name.text().as_bytes(),
            field.value.bytes(),
        ));
    }
    fields
}

pub(crate) struct Mux {
    connection: Connection,
    inbox: Vec<u8>,
}

impl Mux {
    pub(crate) fn boot(exchange: &mut Exchange) -> Result<Self, Error> {
        let (connection, start) = Connection::start(Settings::default()).map_err(Error::Http2)?;
        exchange.send(&start)?;
        Ok(Self {
            connection,
            inbox: Vec::new(),
        })
    }

    pub(crate) fn ask(
        &mut self,
        exchange: &mut Exchange,
        method: Method,
        uri: &Uri,
        body: &[u8],
    ) -> Result<Response, Error> {
        let mut headers = None;
        let mut payload = Vec::new();
        let mut ended = false;
        let mut opened = false;
        while !ended {
            if !opened && self.connection.ready() {
                let id = self.connection.streams().next().map_err(|_| Error::Usage)?;
                let fin = body.is_empty();
                let frames = self
                    .connection
                    .headers(id, &asked(&method, uri, body, &exchange.client.extra), fin)
                    .map_err(|_| Error::Usage)?;
                emit(exchange, &self.connection, &frames)?;
                if !fin {
                    let data = Frame::Data {
                        stream: id,
                        fin: true,
                        pad: None,
                        data: body.to_vec(),
                    };
                    self.connection.send(&data).map_err(|_| Error::Usage)?;
                    emit(exchange, &self.connection, &[data])?;
                }
                opened = true;
            }
            self.inbox.extend(exchange.gather()?);
            let codec = self.connection.inbound();
            while let Some((frame, used)) = codec.decode(&self.inbox)? {
                self.inbox.drain(..used);
                let reaction = self.connection.receive(&frame).map_err(|_| Error::Usage)?;
                emit(exchange, &self.connection, &reaction.reply)?;
                if let Some(block) = reaction.block {
                    headers = Some(block.fields);
                    ended = block.fin;
                }
                if let Frame::Data { data, fin, .. } = frame {
                    payload.extend(data);
                    ended = fin;
                }
            }
        }
        let fields = headers.ok_or(Error::Short)?;
        Ok(Response {
            head: status(&fields)?,
            body: payload,
        })
    }
}

fn emit(exchange: &mut Exchange, connection: &Connection, frames: &[Frame]) -> Result<(), Error> {
    let codec = connection.outbound();
    for frame in frames {
        exchange.send(&codec.encode(frame)?)?;
    }
    Ok(())
}

fn status(fields: &[Header]) -> Result<Head, Error> {
    let mut code = None;
    let mut list = Vec::new();
    for field in fields {
        if field.name == b":status" {
            let text = std::str::from_utf8(&field.value).map_err(|_| Error::Usage)?;
            code = Some(text.parse().map_err(|_| Error::Usage)?);
            continue;
        }
        if field.name.first() == Some(&b':') {
            continue;
        }
        list.push(Field {
            name: Name::new(std::str::from_utf8(&field.name).map_err(|_| Error::Usage)?)?,
            value: Value::new(&field.value)?,
        });
    }
    Ok(Head {
        version: Version::Http11,
        status: Status::new(code.ok_or(Error::Short)?)?,
        reason: String::new(),
        fields: list,
    })
}
