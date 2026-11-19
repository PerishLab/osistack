use super::scan::{Scan, elements, tchar};
use super::{Alternative, Defect, Directive, Origin};
use std::net::{Ipv4Addr, Ipv6Addr};

const LIMIT: usize = 8192;
const DAY: u64 = 86400;
const CEIL: u64 = 1 << 31;

impl Directive {
    pub fn parse(text: &str, origin: &Origin) -> Result<Directive, Defect> {
        if text.len() > LIMIT {
            return Err(Defect::Large);
        }
        if !text
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..0x7f).contains(&byte))
        {
            return Err(Defect::Syntax);
        }
        let items: Vec<&str> = elements(text)
            .into_iter()
            .map(|item| item.trim_matches([' ', '\t']))
            .filter(|item| !item.is_empty())
            .collect();
        if items.is_empty() {
            return Err(Defect::Empty);
        }
        if items.contains(&"clear") {
            return Ok(Directive::Clear);
        }
        let found: Result<Vec<Alternative>, Defect> =
            items.iter().map(|item| alternative(item, origin)).collect();
        Ok(Directive::Offer(found?))
    }
}

fn digit(byte: u8) -> Result<u8, Defect> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Defect::Escape),
    }
}

fn unescape(raw: &[u8]) -> Result<Vec<u8>, Defect> {
    if raw.is_empty() {
        return Err(Defect::Syntax);
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        if raw[at] != b'%' {
            out.push(raw[at]);
            at += 1;
            continue;
        }
        let pair = raw.get(at + 1..at + 3).ok_or(Defect::Escape)?;
        let byte = (digit(pair[0])? << 4) | digit(pair[1])?;
        if byte != b'%' && tchar(byte) {
            return Err(Defect::Escape);
        }
        out.push(byte);
        at += 3;
    }
    Ok(out)
}

fn label(text: &str) -> bool {
    let bytes = text.as_bytes();
    let plain = bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
    if !plain || !(1..=63).contains(&bytes.len()) {
        return false;
    }
    !text.starts_with('-') && !text.ends_with('-')
}

fn name(text: &str) -> Result<String, Defect> {
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map(|found| found.to_string())
            .map_err(|_| Defect::Host);
    }
    if let Ok(found) = text.parse::<Ipv4Addr>() {
        return Ok(found.to_string());
    }
    let last = text.rsplit('.').next().unwrap_or_default();
    let digits = last.bytes().all(|byte| byte.is_ascii_digit());
    if text.len() > 253 || digits || !text.split('.').all(label) {
        return Err(Defect::Host);
    }
    Ok(text.to_ascii_lowercase())
}

fn number(digits: &str) -> Option<u32> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let fold = |sum: u32, byte: u8| {
        sum.saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'))
    };
    Some(digits.bytes().fold(0, fold))
}

fn authority(content: &[u8], origin: &Origin) -> Result<(String, u16), Defect> {
    let text = std::str::from_utf8(content).map_err(|_| Defect::Host)?;
    let (host, digits) = text.rsplit_once(':').ok_or(Defect::Port)?;
    let port = number(digits)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(Defect::Port)?;
    if host.is_empty() {
        return Ok((origin.host.clone(), port));
    }
    Ok((name(host)?, port))
}

#[derive(Default)]
struct Params {
    ma: Option<u64>,
    persist: Option<bool>,
}

impl Params {
    fn age(&mut self, value: &[u8]) -> Result<(), Defect> {
        let text = std::str::from_utf8(value).map_err(|_| Defect::Age)?;
        let found = number(text).ok_or(Defect::Age)?;
        match self.ma.replace(u64::from(found).min(CEIL)) {
            Some(_) => Err(Defect::Repeat),
            None => Ok(()),
        }
    }

    fn keep(&mut self, value: &[u8]) -> Result<(), Defect> {
        match self.persist.replace(value == b"1") {
            Some(_) => Err(Defect::Repeat),
            None => Ok(()),
        }
    }

    fn take(&mut self, key: &[u8], value: &[u8]) -> Result<(), Defect> {
        match key {
            b"ma" => self.age(value),
            b"persist" => self.keep(value),
            _ => Ok(()),
        }
    }
}

fn alternative(item: &str, origin: &Origin) -> Result<Alternative, Defect> {
    let mut scan = Scan::new(item);
    let protocol = unescape(scan.token())?;
    if !scan.eat(b'=') {
        return Err(Defect::Syntax);
    }
    let (host, port) = authority(&scan.quoted()?, origin)?;
    let mut params = Params::default();
    loop {
        scan.blank();
        if scan.done() {
            break;
        }
        if !scan.eat(b';') {
            return Err(Defect::Syntax);
        }
        scan.blank();
        let key = scan.token();
        if key.is_empty() || !scan.eat(b'=') {
            return Err(Defect::Syntax);
        }
        params.take(key, &scan.value()?)?;
    }
    Ok(Alternative {
        protocol,
        host,
        port,
        age: params.ma.unwrap_or(DAY),
        persist: params.persist.unwrap_or(false),
    })
}
