use crate::client::{Client, Response};
use crate::error::Error;
use crate::exchange::Exchange;
use h1::{Field, Framing, Head, Request, Version};
use h2::{Connection, Frame, Header, Settings};
use http::{Method, Name, Scheme, Status, Uri, Value};
use std::time::Instant;

pub struct Clock<'a> {
    client: &'a Client,
    deadline: Instant,
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
        let bodiless = method.text() == "HEAD" || method.text() == "CONNECT";
        let mut exchange = Exchange::until(self.client, uri.host(), uri.port(), self.deadline)?;
        if uri.scheme() == Scheme::Https {
            exchange.wire(uri.host())?;
        }
        if exchange.h2() {
            return call(&mut exchange, method, uri, body);
        }
        let fields = Client::fields(&method, uri, body, true)?;
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

fn asked(method: &Method, uri: &Uri, body: &[u8]) -> Vec<Header> {
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
    fields
}

fn call(
    exchange: &mut Exchange,
    method: Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Response, Error> {
    let (mut connection, start) = Connection::start(Settings::default());
    exchange.send(&start)?;
    let mut inbox = Vec::new();
    let mut headers = None;
    let mut payload = Vec::new();
    let mut ended = false;
    let mut opened = false;
    while !ended {
        if !opened && connection.ready() {
            let id = connection.streams().next().map_err(|_| Error::Usage)?;
            let fin = body.is_empty();
            let frames = connection
                .headers(id, &asked(&method, uri, body), fin)
                .map_err(|_| Error::Usage)?;
            emit(exchange, &connection, &frames)?;
            if !fin {
                let data = Frame::Data {
                    stream: id,
                    fin: true,
                    pad: None,
                    data: body.to_vec(),
                };
                connection.send(&data).map_err(|_| Error::Usage)?;
                emit(exchange, &connection, &[data])?;
            }
            opened = true;
        }
        inbox.extend(exchange.gather()?);
        let codec = connection.inbound();
        while let Some((frame, used)) = codec.decode(&inbox)? {
            inbox.drain(..used);
            let reaction = connection.receive(&frame).map_err(|_| Error::Usage)?;
            emit(exchange, &connection, &reaction.reply)?;
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
