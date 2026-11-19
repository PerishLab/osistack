use tls::x509::{Certificate, Flaw, Name, Time};

pub const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub const RSA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
pub const ECDSA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const ALT: &[u8] = &[0x55, 0x1d, 0x11];
pub const BASIC: &[u8] = &[0x55, 0x1d, 0x13];
pub const USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
pub const PURPOSE: &[u8] = &[0x55, 0x1d, 0x25];
pub const COMMON: &[u8] = &[0x55, 0x04, 0x03];

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub struct Dice(u64);

impl Dice {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    pub fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let size = content.len();
    let mut out = vec![tag];
    if size < 128 {
        out.push(size as u8);
    } else {
        let raw: Vec<u8> = size
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | raw.len() as u8);
        out.extend(raw);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn int(content: &[u8]) -> Vec<u8> {
    tlv(0x02, content)
}

pub fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

pub fn bits(unused: u8, data: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[unused][..], data].concat())
}

pub fn alg(id: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    seq(&[&oid(id), params.unwrap_or(&[])])
}

pub fn name(common: &str) -> Vec<u8> {
    let pair = seq(&[&oid(COMMON), &tlv(0x0c, common.as_bytes())]);
    seq(&[&tlv(0x31, &pair)])
}

pub fn utc(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}

pub fn extension(id: &[u8], critical: Option<bool>, value: &[u8]) -> Vec<u8> {
    let flag = match critical {
        None => vec![],
        Some(true) => tlv(1, &[0xff]),
        Some(false) => tlv(1, &[0x00]),
    };
    seq(&[&oid(id), &flag, &tlv(0x04, value)])
}

pub fn wrap(extensions: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = extensions.iter().map(|each| each.as_slice()).collect();
    tlv(0xa3, &seq(&refs))
}

pub fn point() -> Vec<u8> {
    let mut out = vec![0x04];
    out.extend((1..=64u8).collect::<Vec<u8>>());
    out
}

pub fn spki(curve: &[u8], point: &[u8]) -> Vec<u8> {
    let algorithm = alg(EC, Some(&oid(curve)));
    seq(&[&algorithm, &bits(0, point)])
}

pub struct Parts {
    pub version: Vec<u8>,
    pub serial: Vec<u8>,
    pub algorithm: Vec<u8>,
    pub issuer: Vec<u8>,
    pub validity: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub unique: Vec<u8>,
    pub extensions: Vec<u8>,
    pub outer: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Parts {
    pub fn base() -> Self {
        let validity = seq(&[&utc("260101000000Z"), &utc("300101000000Z")]);
        Self {
            version: tlv(0xa0, &int(&[2])),
            serial: int(&[1]),
            algorithm: alg(ECDSA256, None),
            issuer: name("ca"),
            validity,
            subject: name("leaf"),
            spki: spki(P256, &point()),
            unique: vec![],
            extensions: vec![],
            outer: alg(ECDSA256, None),
            signature: bits(0, &[1, 2, 3, 4]),
        }
    }

    pub fn with(extensions: &[Vec<u8>]) -> Self {
        Self {
            extensions: wrap(extensions),
            ..Self::base()
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let tbs = seq(&[
            &self.version,
            &self.serial,
            &self.algorithm,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.spki,
            &self.unique,
            &self.extensions,
        ]);
        seq(&[&tbs, &self.outer, &self.signature])
    }

    pub fn parse(&self) -> Result<Certificate, Flaw> {
        Certificate::parse(&self.build())
    }
}

pub fn flaw(parts: &Parts) -> Flaw {
    parts.parse().unwrap_err()
}

pub fn single(id: &[u8], critical: Option<bool>, value: &[u8]) -> Parts {
    Parts::with(&[extension(id, critical, value)])
}

pub fn when(date: (u16, u8, u8), clock: (u8, u8, u8)) -> Time {
    Time {
        year: date.0,
        month: date.1,
        day: date.2,
        hour: clock.0,
        minute: clock.1,
        second: clock.2,
    }
}

pub fn shape(name: &Name) -> Vec<String> {
    let each = |item: &tls::x509::Attribute| {
        let value = String::from_utf8_lossy(&item.value).to_string();
        format!("{}/{:02x}/{}", item.id, item.tag, value)
    };
    name.attributes.iter().map(each).collect()
}

pub fn listed(cert: &Certificate) -> Vec<String> {
    let each =
        |item: &tls::x509::Extension| format!("{}/{}/{}", item.id, item.critical, item.value.len());
    cert.extensions.iter().map(each).collect()
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|part| part == needle)
}

pub fn load(text: &str) -> (Vec<u8>, Certificate) {
    let wire = hex(text);
    let cert = Certificate::parse(&wire).unwrap();
    (wire, cert)
}
