pub const ECDSA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub const ALT: &[u8] = &[0x55, 0x1d, 0x11];
pub const COMMON: &[u8] = &[0x55, 0x04, 0x03];

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

pub fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

pub fn bits(unused: u8, data: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[unused][..], data].concat())
}

pub fn alg(id: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    seq(&[&oid(id), params.unwrap_or(&[])])
}

pub fn named(common: &str, tag: u8) -> Vec<u8> {
    let pair = seq(&[&oid(COMMON), &tlv(tag, common.as_bytes())]);
    seq(&[&tlv(0x31, &pair)])
}

pub fn name(common: &str) -> Vec<u8> {
    named(common, 0x0c)
}

pub fn dns(text: &str) -> Vec<u8> {
    tlv(0x82, text.as_bytes())
}

pub fn ip(octets: &[u8]) -> Vec<u8> {
    tlv(0x87, octets)
}

pub fn email(text: &str) -> Vec<u8> {
    tlv(0x81, text.as_bytes())
}

pub fn uri(text: &str) -> Vec<u8> {
    tlv(0x86, text.as_bytes())
}

fn extensions(entries: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = entries.iter().map(|each| each.as_slice()).collect();
    let value = seq(&refs);
    let one = seq(&[&oid(ALT), &tlv(0x04, &value)]);
    tlv(0xa3, &seq(&[&one]))
}

pub fn build(subject: &[u8], issuer: &str, names: Option<&[Vec<u8>]>, seed: u8) -> Vec<u8> {
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"300101000000Z")]);
    let mut point = vec![0x04];
    point.extend((1..=64u8).map(|byte| byte.wrapping_add(seed)));
    let spki = seq(&[&alg(EC, Some(&oid(P256))), &bits(0, &point)]);
    let version = tlv(0xa0, &tlv(0x02, &[2]));
    let serial = tlv(0x02, &[1, seed | 1]);
    let extra = names.map(extensions).unwrap_or_default();
    let tbs = seq(&[
        &version,
        &serial,
        &alg(ECDSA256, None),
        &name(issuer),
        &validity,
        subject,
        &spki,
        &extra,
    ]);
    seq(&[&tbs, &alg(ECDSA256, None), &bits(0, &[1, 2, 3, 4])])
}

pub fn encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut word = 0u32;
        for at in 0..3 {
            word = (word << 8) | u32::from(*chunk.get(at).unwrap_or(&0));
        }
        for at in 0..4 {
            if at <= chunk.len() {
                out.push(TABLE[((word >> (18 - 6 * at)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn pem(label: &str, data: &[u8], width: usize, eol: &str) -> String {
    let text = encode(data);
    let mut out = format!("-----BEGIN {label}-----{eol}");
    for line in text.as_bytes().chunks(width) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push_str(eol);
    }
    out.push_str(&format!("-----END {label}-----{eol}"));
    out
}
