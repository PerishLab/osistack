use super::Request;
use crate::error::Error;
use crate::field::{Name, Value};
use crate::method::Method;
use crate::uri::Uri;

pub(super) fn parse(
    method: Method,
    target: &str,
    fields: Vec<(Name, Value)>,
) -> Result<Request, Error> {
    if target == "*" {
        let uri = host(&fields)?;
        return Request::star(&uri, stripped(fields));
    }
    if method.text() == "CONNECT" {
        let uri = Uri::parse(&format!("http://{target}"))?;
        return Request::new(method, &uri, stripped(fields));
    }
    if let Ok(uri) = Uri::parse(target) {
        aligned(&uri, &fields)?;
        return Request::new(method, &uri, stripped(fields));
    }
    if !target.starts_with('/') {
        return Err(Error::Target);
    }
    let uri = joined(&host(&fields)?, target)?;
    Request::new(method, &uri, stripped(fields))
}

fn aligned(uri: &Uri, fields: &[(Name, Value)]) -> Result<(), Error> {
    match host(fields) {
        Err(Error::Host) => Ok(()),
        Err(error) => Err(error),
        Ok(found) => {
            if found.authority() == uri.authority() {
                Ok(())
            } else {
                Err(Error::Host)
            }
        }
    }
}

fn host(fields: &[(Name, Value)]) -> Result<Uri, Error> {
    let mut found = None;
    for (name, value) in fields {
        if name.text() == "host" {
            if found.is_some() {
                return Err(Error::Duplicate);
            }
            found = Some(value.bytes());
        }
    }
    let host = found.ok_or(Error::Host)?;
    let text = std::str::from_utf8(host).map_err(|_| Error::Host)?;
    Uri::parse(&format!("http://{text}/"))
}

fn stripped(fields: Vec<(Name, Value)>) -> Vec<(Name, Value)> {
    fields
        .into_iter()
        .filter(|(name, _)| name.text() != "host")
        .collect()
}

fn joined(base: &Uri, target: &str) -> Result<Uri, Error> {
    Uri::parse(&format!(
        "{}://{}{}",
        base.scheme().text(),
        base.authority(),
        target
    ))
}
