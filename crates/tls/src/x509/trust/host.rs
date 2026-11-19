use super::Refusal;
use crate::x509::{Certificate, General};
use std::net::IpAddr;

const LONGEST: usize = 253;
const LABEL: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Dns(String),
    Ip(Vec<u8>),
}

fn letters(label: &str) -> bool {
    let bytes = label.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    let plain = bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
    if !plain || bytes.len() > LABEL {
        return false;
    }
    *first != b'-' && *last != b'-'
}

impl Host {
    pub fn parse(text: &str) -> Result<Host, Refusal> {
        if let Ok(address) = text.parse::<IpAddr>() {
            let octets = match address {
                IpAddr::V4(found) => found.octets().to_vec(),
                IpAddr::V6(found) => found.octets().to_vec(),
            };
            return Ok(Host::Ip(octets));
        }
        let bare = text.strip_suffix('.').unwrap_or(text);
        if bare.is_empty() || bare.len() > LONGEST || !bare.split('.').all(letters) {
            return Err(Refusal::Host);
        }
        let last = bare.rsplit('.').next().unwrap_or_default();
        if last.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Refusal::Host);
        }
        Ok(Host::Dns(bare.to_ascii_lowercase()))
    }
}

fn dns(presented: &str, reference: &str) -> bool {
    let text = presented.to_ascii_lowercase();
    let Some(rest) = text.strip_prefix("*.") else {
        return !text.contains('*') && text == reference;
    };
    let Some((_, tail)) = reference.split_once('.') else {
        return false;
    };
    let sound = rest.contains('.') && rest.split('.').all(|label| !label.is_empty());
    sound && !rest.contains('*') && tail == rest
}

pub fn matches(names: &[General], host: &Host) -> bool {
    names.iter().any(|name| match (name, host) {
        (General::Dns(text), Host::Dns(reference)) => dns(text, reference),
        (General::Ip(bytes), Host::Ip(octets)) => bytes == octets,
        _ => false,
    })
}

pub fn verify(cert: &Certificate, host: &Host) -> Result<(), Refusal> {
    let names = cert.alt.as_deref().unwrap_or_default();
    let usable = names
        .iter()
        .any(|name| matches!(name, General::Dns(_) | General::Ip(_)));
    if !usable {
        return Err(Refusal::Missing);
    }
    if matches(names, host) {
        return Ok(());
    }
    Err(Refusal::Mismatch)
}
