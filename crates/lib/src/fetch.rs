use crate::client::{Client, Response};
use crate::error::Error;
use h1::Field;
use http::{Method, Name, Request, Scheme, Uri, Value};
use std::fs;
use std::time::Duration;

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
    if let Some(total) = taken.total {
        client.total = total;
    }
    client.extra = taken.extra;
    if let Some(via) = taken.proxy {
        client.via = Some(via);
    }
    if let Some(list) = taken.noproxy.as_deref()
        && bypass(uri.host(), list)
    {
        client.via = None;
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

struct Parsed {
    method: Method,
    target: String,
    body: Vec<u8>,
    output: Option<String>,
    fail: bool,
    total: Option<Duration>,
    written: Option<String>,
    extra: Vec<Field>,
    retry: u32,
    noproxy: Option<String>,
    proxy: Option<Uri>,
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
            fail: false,
            total: None,
            written: None,
            extra: Vec::new(),
            retry: 0,
            noproxy: None,
            proxy: None,
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
            "-H" | "--header" => {
                self.extra.push(header(needed(args, at)?)?);
                Ok(at + 2)
            }
            "--retry" => {
                self.retry = count(needed(args, at)?)?;
                Ok(at + 2)
            }
            "--noproxy" => {
                self.noproxy = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            "-x" | "--proxy" => {
                let uri = Uri::parse(needed(args, at)?).map_err(|_| Error::Usage)?;
                if uri.scheme() != Scheme::Http {
                    return Err(Error::Usage);
                }
                self.proxy = Some(uri);
                Ok(at + 2)
            }
            "-o" | "--output" => {
                self.output = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            "-f" | "--fail" => {
                self.fail = true;
                Ok(at + 1)
            }
            "--max-time" => {
                self.total = Some(limit(needed(args, at)?)?);
                Ok(at + 2)
            }
            "-w" | "--write-out" => {
                self.written = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            "-s" | "--silent" | "-S" | "--show-error" | "-L" | "--location" => Ok(at + 1),
            flag if flag.starts_with('-') && !flag.starts_with("--") => {
                self.shorts(flag)?;
                Ok(at + 1)
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

    fn shorts(&mut self, flag: &str) -> Result<(), Error> {
        if flag.len() < 2 {
            return Err(Error::Usage);
        }
        for unit in flag.chars().skip(1) {
            match unit {
                'f' => self.fail = true,
                's' | 'S' | 'L' => {}
                _ => return Err(Error::Usage),
            }
        }
        Ok(())
    }
}

fn header(text: &str) -> Result<Field, Error> {
    let (name, value) = text.split_once(':').ok_or(Error::Usage)?;
    if name.is_empty() {
        return Err(Error::Usage);
    }
    let name = Name::new(name).map_err(|_| Error::Usage)?;
    let value = value.strip_prefix(' ').unwrap_or(value);
    let value = Value::new(value.as_bytes()).map_err(|_| Error::Usage)?;
    Ok(Field { name, value })
}

fn bypass(host: &str, list: &str) -> bool {
    list.split(',')
        .map(str::trim)
        .any(|item| item == "*" || item == host)
}

fn count(text: &str) -> Result<u32, Error> {
    text.parse().map_err(|_| Error::Usage)
}

fn needed<'a>(args: &[&'a str], at: usize) -> Result<&'a str, Error> {
    args.get(at + 1).copied().ok_or(Error::Usage)
}

fn limit(text: &str) -> Result<Duration, Error> {
    let secs: f64 = text.parse().map_err(|_| Error::Usage)?;
    if !secs.is_finite() || secs < 0.0 {
        return Err(Error::Usage);
    }
    Ok(Duration::from_secs_f64(secs))
}
