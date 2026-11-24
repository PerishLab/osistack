use crate::client::Http3;
use crate::error::Error;
use h1::Field;
use http::{Method, Name, Scheme, Uri, Value};
use std::time::Duration;

pub(crate) struct Parsed {
    pub(crate) method: Method,
    pub(crate) target: String,
    pub(crate) body: Vec<u8>,
    pub(crate) output: Option<String>,
    pub(crate) fail: bool,
    pub(crate) total: Option<Duration>,
    pub(crate) written: Option<String>,
    pub(crate) extra: Vec<Field>,
    pub(crate) retry: u32,
    pub(crate) noproxy: Option<String>,
    pub(crate) proxy: Option<Uri>,
    pub(crate) follow: bool,
    pub(crate) head: bool,
    pub(crate) cacert: Option<String>,
    pub(crate) dump: Option<String>,
    pub(crate) connect: Option<Duration>,
    pub(crate) http3: Option<Http3>,
}

impl Parsed {
    pub(crate) fn read(args: &[&str]) -> Result<Self, Error> {
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
            follow: false,
            head: false,
            cacert: None,
            dump: None,
            connect: None,
            http3: None,
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
                let method = Method::new(needed(args, at)?)?;
                if self.head && method.text() != "HEAD" {
                    return Err(Error::Usage);
                }
                self.method = method;
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
            "-A" | "--user-agent" => {
                let text = format!("user-agent: {}", needed(args, at)?);
                self.extra.push(header(&text)?);
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
            "--connect-timeout" => {
                self.connect = Some(limit(needed(args, at)?)?);
                Ok(at + 2)
            }
            "-w" | "--write-out" => {
                self.written = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            "--cacert" => {
                self.cacert = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            "-D" | "--dump-header" => {
                self.dump = Some(needed(args, at)?.to_owned());
                Ok(at + 2)
            }
            "-I" | "--head" => {
                self.heading()?;
                Ok(at + 1)
            }
            "-s" | "--silent" | "-S" | "--show-error" => Ok(at + 1),
            "-L" | "--location" => {
                self.follow = true;
                Ok(at + 1)
            }
            "--http3" => {
                self.triple(Http3::Prefer)?;
                Ok(at + 1)
            }
            "--http3-only" => {
                self.triple(Http3::Only)?;
                Ok(at + 1)
            }
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

    fn heading(&mut self) -> Result<(), Error> {
        if self.method.text() != "GET" && self.method.text() != "HEAD" {
            return Err(Error::Usage);
        }
        self.head = true;
        self.method = Method::new("HEAD")?;
        Ok(())
    }
    fn triple(&mut self, http3: Http3) -> Result<(), Error> {
        if self.http3.is_some() {
            return Err(Error::Usage);
        }
        self.http3 = Some(http3);
        Ok(())
    }

    fn shorts(&mut self, flag: &str) -> Result<(), Error> {
        if flag.len() < 2 {
            return Err(Error::Usage);
        }
        for unit in flag.chars().skip(1) {
            match unit {
                'f' => self.fail = true,
                's' | 'S' => {}
                'L' => self.follow = true,
                'I' => self.heading()?,
                _ => return Err(Error::Usage),
            }
        }
        Ok(())
    }
}

pub(crate) fn header(text: &str) -> Result<Field, Error> {
    let (name, value) = text.split_once(':').ok_or(Error::Usage)?;
    if name.is_empty() {
        return Err(Error::Usage);
    }
    let name = Name::new(name).map_err(|_| Error::Usage)?;
    let value = value.strip_prefix(' ').unwrap_or(value);
    let value = Value::new(value.as_bytes()).map_err(|_| Error::Usage)?;
    Ok(Field { name, value })
}

pub(crate) fn bypass(host: &str, list: &str) -> bool {
    list.split(',')
        .map(str::trim)
        .any(|item| item == "*" || item == host)
}

pub(crate) fn count(text: &str) -> Result<u32, Error> {
    text.parse().map_err(|_| Error::Usage)
}

fn needed<'a>(args: &[&'a str], at: usize) -> Result<&'a str, Error> {
    args.get(at + 1).copied().ok_or(Error::Usage)
}

pub(crate) fn limit(text: &str) -> Result<Duration, Error> {
    let secs: f64 = text.parse().map_err(|_| Error::Usage)?;
    if !secs.is_finite() || secs < 0.0 {
        return Err(Error::Usage);
    }
    Ok(Duration::from_secs_f64(secs))
}
