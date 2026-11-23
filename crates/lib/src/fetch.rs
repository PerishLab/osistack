use crate::client::{Client, Response};
use crate::error::Error;
use http::{Method, Request, Scheme, Uri};
use std::fs;

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
    let taken = Parsed::read(args)?;
    let uri = Uri::parse(&taken.target)?;
    if uri.scheme() != Scheme::Http {
        return Err(Error::Scheme);
    }
    let request = Request::new(taken.method, &uri, Vec::new())?;
    let response = fetch(&request, &taken.body)?;
    if let Some(path) = taken.output {
        fs::write(path, &response.body)?;
    }
    Ok(response)
}

struct Parsed {
    method: Method,
    target: String,
    body: Vec<u8>,
    output: Option<String>,
}

impl Parsed {
    fn read(args: &[&str]) -> Result<Self, Error> {
        let args = if args.first() == Some(&"fetch") {
            &args[1..]
        } else {
            args
        };
        let mut taken = Self {
            method: Method::new("GET")?,
            target: String::new(),
            body: Vec::new(),
            output: None,
        };
        let mut at = 0;
        while at < args.len() {
            at = taken.step(args, at)?;
        }
        if taken.target.is_empty() {
            Err(Error::Usage)
        } else {
            Ok(taken)
        }
    }

    fn step(&mut self, args: &[&str], at: usize) -> Result<usize, Error> {
        match args[at] {
            "--method" => {
                self.method = Method::new(needed(args, at)?)?;
                Ok(at + 2)
            }
            "--data" => {
                self.body = needed(args, at)?.as_bytes().to_vec();
                Ok(at + 2)
            }
            "-o" | "--output" => {
                self.output = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            flag if flag.starts_with('-') => Err(Error::Usage),
            text => {
                if !self.target.is_empty() {
                    return Err(Error::Usage);
                }
                self.target = text.to_owned();
                Ok(at + 1)
            }
        }
    }
}

fn needed<'a>(args: &[&'a str], at: usize) -> Result<&'a str, Error> {
    args.get(at + 1).copied().ok_or(Error::Usage)
}
