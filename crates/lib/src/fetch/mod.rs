use crate::Roots;
use crate::client::{Client, Response};
use crate::error::Error;
use http::{Request, Scheme, Uri};
use std::fs;

mod flags;
use flags::{Parsed, bypass};

pub struct Applied {
    pub response: Response,
    pub written: Option<String>,
}

pub fn fetch(request: &Request, body: &[u8]) -> Result<Response, Error> {
    if request.scheme() != Scheme::Http {
        return Err(Error::Scheme);
    }
    let path = if request.path().is_empty() {
        "/"
    } else {
        request.path()
    };
    let text = format!(
        "{}://{}{}",
        request.scheme().text(),
        request.authority(),
        path
    );
    let uri = Uri::parse(&text)?;
    Client::default().fetch(request.method().clone(), &uri, body)
}

pub fn command(args: &[&str]) -> Result<Response, Error> {
    Ok(applied(args)?.response)
}

pub fn applied(args: &[&str]) -> Result<Applied, Error> {
    driven(Client::default(), args)
}

pub fn driven(mut client: Client, args: &[&str]) -> Result<Applied, Error> {
    let taken = Parsed::read(args)?;
    let uri = Uri::parse(&taken.target)?;
    if uri.scheme() != Scheme::Http && uri.scheme() != Scheme::Https {
        return Err(Error::Scheme);
    }
    client.total = taken.total.unwrap_or(client.total);
    client.connect = taken.connect.unwrap_or(client.connect);
    client.extra = taken.extra;
    client.follow = taken.follow;
    if let Some(via) = taken.proxy {
        client.via = Some(via);
    }
    if let Some(list) = taken.noproxy.as_deref()
        && bypass(uri.host(), list)
    {
        client.via = None;
    }
    if let Some(path) = taken.cacert {
        let text = fs::read_to_string(path).map_err(|_| Error::Trust)?;
        client.roots = Roots::pem(&text).map_err(|_| Error::Trust)?;
    }
    if let Some(http3) = taken.http3 {
        if uri.scheme() != Scheme::Https {
            return Err(Error::Usage);
        }
        client.http3 = http3;
    }
    if uri.scheme() == Scheme::Https && client.roots.count() == 0 {
        return Err(Error::Trust);
    }
    let mut result = client.fetch(taken.method.clone(), &uri, &taken.body);
    for _ in 0..taken.retry {
        if result.is_ok() {
            break;
        }
        result = client.fetch(taken.method.clone(), &uri, &taken.body);
    }
    let response = result?;
    if taken.fail && response.head.status.get() >= 400 {
        return Err(Error::Status);
    }
    if let Some(path) = taken.output {
        fs::write(path, &response.body)?;
    }
    if let Some(path) = taken.dump {
        fs::write(path, response.listed())?;
    }
    let written = taken
        .written
        .as_deref()
        .map(|format| expand(&response, format));
    Ok(Applied { response, written })
}

fn expand(response: &Response, format: &str) -> String {
    format
        .replace("%{http_code}", &response.head.status.get().to_string())
        .replace("%{size_download}", &response.body.len().to_string())
}
