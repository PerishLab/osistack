use super::{Request, make};
use crate::error::Error;
use crate::field::{Name, Value};
use crate::method::Method;
use crate::uri::Scheme;

struct Decode {
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<String>,
    path: Option<String>,
    fields: Vec<(Name, Value)>,
    step: u8,
}

pub(super) fn run(lines: &[(Vec<u8>, Vec<u8>)]) -> Result<Request, Error> {
    let mut decode = Decode {
        method: None,
        scheme: None,
        authority: None,
        path: None,
        fields: Vec::new(),
        step: 0,
    };
    for (name, value) in lines {
        decode.feed(name, value)?;
    }
    decode.finish()
}

impl Decode {
    fn feed(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        if name.starts_with(b":") {
            if self.step == 5 {
                return Err(Error::Order);
            }
            self.pseudo(name, value)
        } else {
            self.step = 5;
            let text = std::str::from_utf8(name).map_err(|_| Error::Character)?;
            self.fields.push((Name::new(text)?, Value::new(value)?));
            Ok(())
        }
    }

    fn pseudo(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        let text = std::str::from_utf8(value).map_err(|_| Error::Character)?;
        match (name, self.step) {
            (b":method", 0) => {
                self.method = Some(Method::new(text)?);
                self.step = 1;
                Ok(())
            }
            (b":scheme", 1) => {
                self.scheme = Some(scheme(text)?);
                self.step = 2;
                Ok(())
            }
            (b":authority", 2) => {
                self.authority = Some(text.to_owned());
                self.step = 3;
                Ok(())
            }
            (b":path", 3) => self.attach(text),
            (b":method" | b":scheme" | b":authority" | b":path", _) => Err(Error::Order),
            (b":status" | b":protocol", _) => Err(Error::Pseudo),
            _ if name.starts_with(b":") => Err(Error::Pseudo),
            _ => Err(Error::Order),
        }
    }

    fn attach(&mut self, text: &str) -> Result<(), Error> {
        if self
            .method
            .as_ref()
            .is_some_and(|method| method.text() == "CONNECT")
        {
            return Err(Error::Target);
        }
        self.path = Some(text.to_owned());
        self.step = 4;
        Ok(())
    }

    fn finish(self) -> Result<Request, Error> {
        let method = self.method.ok_or(Error::Pseudo)?;
        let scheme = self.scheme.ok_or(Error::Pseudo)?;
        let authority = self.authority.ok_or(Error::Pseudo)?;
        let path = if method.text() == "CONNECT" {
            String::new()
        } else {
            self.path.ok_or(Error::Pseudo)?
        };
        make(Request {
            method,
            scheme,
            authority,
            path,
            fields: self.fields,
        })
    }
}

fn scheme(text: &str) -> Result<Scheme, Error> {
    match text {
        "http" => Ok(Scheme::Http),
        "https" => Ok(Scheme::Https),
        _ => Err(Error::Scheme),
    }
}
