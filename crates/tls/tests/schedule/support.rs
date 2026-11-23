use crate::sign::{share, signed};
use crypto::{Aead, Group, Hash, Running};
use tls::x509::Time;
use tls::x509::trust::Roots;
use tls::{
    Accepted, Chain, Content, Encrypted, Entry, Finished, Hello, Kind, Layer, Master, Message,
    Record, Reply, Schedule, Share, Typed, Verify,
};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn schedule(shared: &str) -> Schedule {
    Schedule::new(Hash::Sha256, &hex(shared)).unwrap()
}

pub fn master(shared: &str) -> Master {
    schedule(shared).master().unwrap()
}

pub(crate) const HOST: &str = "example.test";
const ECDSA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const COMMON: &[u8] = &[0x55, 0x04, 0x03];
const ALT: &[u8] = &[0x55, 0x1d, 0x11];

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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

pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub(crate) fn alg(id: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    seq(&[&tlv(0x06, id), params.unwrap_or(&[])])
}

pub(crate) fn name(common: &str) -> Vec<u8> {
    let pair = seq(&[&tlv(0x06, COMMON), &tlv(0x0c, common.as_bytes())]);
    seq(&[&tlv(0x31, &pair)])
}

pub(crate) fn bits(data: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0][..], data].concat())
}

pub(crate) fn cert(host: &str) -> Vec<u8> {
    let point = share(host);
    let spki = seq(&[&alg(EC, Some(&tlv(0x06, P256))), &bits(&point)]);
    let names = seq(&[&tlv(0x82, host.as_bytes())]);
    let ext = tlv(0xa3, &seq(&[&seq(&[&tlv(0x06, ALT), &tlv(0x04, &names)])]));
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"300101000000Z")]);
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &tlv(0x02, &[1]),
        &alg(ECDSA256, None),
        &name(host),
        &validity,
        &name(host),
        &spki,
        &ext,
    ]);
    seq(&[&tbs, &alg(ECDSA256, None), &bits(&signed(host, &tbs))])
}

pub(crate) fn offered() -> Share {
    Share {
        group: 0x0017,
        key: Group::Secp256r1.public(&[9; 32]).unwrap(),
    }
}

pub(crate) fn hello() -> Hello {
    Hello::start(HOST.as_bytes(), &[b"h2".to_vec()], offered(), [7u8; 32]).unwrap()
}

pub(crate) fn reply() -> Reply {
    Reply {
        random: [5u8; 32],
        session: Vec::new(),
        suite: 0x1301,
        extensions: vec![
            Typed::Chosen(Share {
                group: 0x0017,
                key: Group::Secp256r1.public(&[8; 32]).unwrap(),
            })
            .write()
            .unwrap(),
            Typed::Version(0x0304).write().unwrap(),
        ],
    }
}

pub(crate) fn now() -> Time {
    Time {
        year: 2027,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    }
}

pub(crate) fn message(kind: Kind, body: Vec<u8>) -> Vec<u8> {
    Message { kind, body }.write().unwrap()
}

pub(crate) fn roots(der: &[u8]) -> Roots {
    let mut roots = Roots::default();
    roots.add(der).unwrap();
    roots
}

pub(crate) fn shared() -> Vec<u8> {
    Group::Secp256r1
        .agree(&[9; 32], &Group::Secp256r1.public(&[8; 32]).unwrap())
        .unwrap()
}

pub(crate) fn accepted() -> (Hello, Accepted) {
    let hello = hello();
    let accepted = hello.accept(&reply(), &shared()).unwrap();
    (hello, accepted)
}

pub(crate) fn context(transcript: &[u8]) -> Vec<u8> {
    let mut data = vec![0x20; 64];
    data.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    data.push(0);
    data.extend_from_slice(transcript);
    data
}

pub(crate) fn running(hello: &Hello, reply: &Reply) -> Running {
    let mut digest = Running::new(Hash::Sha256);
    digest.update(hello.spoken());
    digest.update(&message(Kind::Reply, reply.write().unwrap()));
    digest
}

pub(crate) fn sealed(accepted: &Accepted, content: Content, data: &[u8]) -> Record {
    let keys = accepted.server().keys(Aead::Aes128).unwrap();
    Layer::new(Aead::Aes128, &keys)
        .unwrap()
        .protect(content, data, 0)
        .unwrap()
}

pub(crate) fn protect(accepted: &Accepted, data: &[u8]) -> Record {
    sealed(accepted, Content::Handshake, data)
}

pub(crate) fn bodies(hello: &Hello, accepted: &Accepted, der: &[u8], flip: bool) -> Vec<u8> {
    let mut digest = running(hello, accepted.reply());
    let mut data = Vec::new();
    let extensions = message(
        Kind::Extensions,
        Encrypted {
            extensions: Vec::new(),
        }
        .write()
        .unwrap(),
    );
    digest.update(&extensions);
    data.extend_from_slice(&extensions);
    let certificate = message(
        Kind::Certificate,
        Chain {
            context: Vec::new(),
            entries: vec![Entry {
                cert: der.to_vec(),
                extensions: Vec::new(),
            }],
        }
        .write()
        .unwrap(),
    );
    digest.update(&certificate);
    data.extend_from_slice(&certificate);
    let verify = message(
        Kind::Verify,
        Verify {
            algorithm: 0x0403,
            signature: signed(HOST, &context(&digest.peek())),
        }
        .write()
        .unwrap(),
    );
    digest.update(&verify);
    data.extend_from_slice(&verify);
    let mut tag = accepted.server().finished(&digest.peek()).unwrap();
    if flip {
        tag[0] ^= 1;
    }
    data.extend_from_slice(&message(
        Kind::Finished,
        Finished { data: tag }.write().unwrap(),
    ));
    data
}

pub(crate) fn packed(hello: &Hello, accepted: &Accepted, der: &[u8], flip: bool) -> Record {
    protect(accepted, &bodies(hello, accepted, der, flip))
}
