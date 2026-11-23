use crate::client::{Client, Response};
use crate::error::Error;
use crate::exchange::Exchange;
use h1::{Framing, Request};
use http::{Method, Scheme, Uri};
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
        if uri.scheme() != Scheme::Http {
            return Err(Error::Scheme);
        }
        let bodiless = method.text() == "HEAD" || method.text() == "CONNECT";
        let fields = Client::fields(&method, uri, body, true)?;
        let request = Request::new(method, target, fields)?.encode()?;
        let mut exchange = Exchange::until(self.client, uri.host(), uri.port(), self.deadline)?;
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
