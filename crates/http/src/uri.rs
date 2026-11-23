use crate::error::Error;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn text(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    pub fn port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uri {
    scheme: Scheme,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

impl Uri {
    pub fn parse(text: &str) -> Result<Uri, Error> {
        if text.is_empty() {
            return Err(Error::Empty);
        }
        if text.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f) {
            return Err(Error::Character);
        }
        let (name, rest) = text.split_once(':').ok_or(Error::Scheme)?;
        let scheme = match name.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(Error::Scheme),
        };
        let rest = rest.strip_prefix("//").ok_or(Error::Host)?;
        let stop = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (host, port) = Part(&rest[..stop]).authority()?;
        let (path, query) = Part(&rest[stop..]).split()?;
        Ok(Uri {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port.unwrap_or(self.scheme.port())
    }

    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) if port != self.scheme.port() => format!("{host}:{port}"),
            _ => host,
        }
    }

    pub fn target(&self) -> String {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        match &self.query {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        }
    }

    pub fn written(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.text(),
            self.authority(),
            self.target()
        )
    }

    pub fn join(&self, target: &str) -> Result<Uri, Error> {
        let target = target.split_once('#').map_or(target, |(body, _)| body);
        if target.is_empty() {
            return Err(Error::Target);
        }
        if named(target) {
            return Uri::parse(target);
        }
        if let Some(rest) = target.strip_prefix("//") {
            return Uri::parse(&format!("{}://{rest}", self.scheme.text()));
        }
        let (path, query) = cut(target);
        let (path, query) = if path.is_empty() {
            let path = if self.path.is_empty() {
                "/".to_owned()
            } else {
                self.path.clone()
            };
            (path, query.or(self.query.as_deref()))
        } else if path.starts_with('/') {
            (dots(path), query)
        } else {
            (dots(&merged(&self.path, path)), query)
        };
        let tail = query.map(|query| format!("?{query}")).unwrap_or_default();
        Uri::parse(&format!(
            "{}://{}{}{tail}",
            self.scheme.text(),
            self.authority(),
            path
        ))
    }
}

struct Part<'a>(&'a str);

impl Part<'_> {
    fn authority(&self) -> Result<(String, Option<u16>), Error> {
        let text = self.0;
        if text.contains('@') {
            return Err(Error::Userinfo);
        }
        let (host, tail) = match text.strip_prefix('[') {
            Some(inner) => {
                let (address, tail) = inner.split_once(']').ok_or(Error::Host)?;
                address.parse::<Ipv6Addr>().map_err(|_| Error::Host)?;
                (address.to_ascii_lowercase(), tail)
            }
            None => {
                let split = text.rfind(':').unwrap_or(text.len());
                (Part(&text[..split]).name()?, &text[split..])
            }
        };
        Ok((host, Part(tail).port()?))
    }

    fn name(&self) -> Result<String, Error> {
        let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte);
        if self.0.is_empty() || !self.0.bytes().all(plain) {
            return Err(Error::Host);
        }
        Ok(self.0.to_ascii_lowercase())
    }

    fn port(&self) -> Result<Option<u16>, Error> {
        let Some(digits) = self.0.strip_prefix(':') else {
            return if self.0.is_empty() {
                Ok(None)
            } else {
                Err(Error::Host)
            };
        };
        if digits.is_empty() {
            return Ok(None);
        }
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Port);
        }
        match digits.parse::<u16>() {
            Ok(0) | Err(_) => Err(Error::Port),
            Ok(number) => Ok(Some(number)),
        }
    }

    fn split(&self) -> Result<(String, Option<String>), Error> {
        let (before, fragment) = match self.0.split_once('#') {
            Some((before, fragment)) => (before, Some(fragment)),
            None => (self.0, None),
        };
        let (path, query) = match before.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (before, None),
        };
        Part(path).check(false)?;
        Part(query.unwrap_or("")).check(true)?;
        Part(fragment.unwrap_or("")).check(true)?;
        Ok((path.to_owned(), query.map(str::to_owned)))
    }

    fn check(&self, query: bool) -> Result<(), Error> {
        let bytes = self.0.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let byte = bytes[at];
            let plain = byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&byte);
            let escaped = byte == b'%' && bytes.get(at + 1..at + 3).is_some_and(hex);
            let marked = query && byte == b'?';
            if !(plain || escaped || marked) {
                return Err(Error::Character);
            }
            at += if escaped { 3 } else { 1 };
        }
        Ok(())
    }
}

fn named(target: &str) -> bool {
    let stop = target.find(['/', '?', '#']).unwrap_or(target.len());
    target[..stop].contains(':')
}

fn cut(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

fn merged(base: &str, rel: &str) -> String {
    match base.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{rel}"),
        None => format!("/{rel}"),
    }
}

fn dots(path: &str) -> String {
    let mut out = Vec::new();
    for part in path.split('/') {
        match part {
            "." => {}
            ".." => {
                let _ = out.pop();
            }
            other => out.push(other),
        }
    }
    let mut text = out.join("/");
    if path.starts_with('/') && !text.starts_with('/') {
        text.insert(0, '/');
    }
    if text.is_empty() {
        "/".to_owned()
    } else {
        text
    }
}

fn hex(pair: &[u8]) -> bool {
    pair.iter().all(u8::is_ascii_hexdigit)
}
