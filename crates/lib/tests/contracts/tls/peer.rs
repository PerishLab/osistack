use super::sign::{share, signed};
use crypto::{Aead, Group, Hash, Running};
use tls::x509::Time;
use tls::x509::trust::Roots;
use tls::{
    Chain, Content, Encrypted, Entry, Error, Finished, Hello, Kind, Layer, Message, Offer, Place,
    Record, Reply, Share, Typed, Verify,
};

const ECDSA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const COMMON: &[u8] = &[0x55, 0x04, 0x03];
const ALT: &[u8] = &[0x55, 0x1d, 0x11];

pub struct Held {
    pub host: String,
    pub der: Vec<u8>,
    pub roots: Roots,
    pub now: Time,
    pub protocol: Option<Vec<u8>>,
}

pub struct Waiting {
    digest: Running,
    client: tls::Traffic,
}

impl Waiting {
    pub fn digest(&self) -> Vec<u8> {
        self.digest.peek()
    }

    pub fn check(&self, spoken: &[u8]) -> Result<(), Error> {
        let (message, used) = Message::parse(spoken, (1 << 24) - 1)?.ok_or(Error::Length)?;
        if used != spoken.len() || message.kind != Kind::Finished {
            return Err(Error::Kind);
        }
        let tag = Finished::parse(&message.body, self.digest.hash().size())?;
        self.client.check(&self.digest.peek(), &tag.data)
    }

    pub fn open(&self, record: &Record) -> Result<Vec<u8>, Error> {
        let keys = self.client.keys(Aead::Aes128)?;
        let opened = Layer::new(Aead::Aes128, &keys)?.unprotect(record)?;
        if opened.content != Content::Handshake {
            return Err(Error::Kind);
        }
        Ok(opened.payload)
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn alg(id: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    seq(&[&tlv(0x06, id), params.unwrap_or(&[])])
}

fn name(common: &str) -> Vec<u8> {
    let pair = seq(&[&tlv(0x06, COMMON), &tlv(0x0c, common.as_bytes())]);
    seq(&[&tlv(0x31, &pair)])
}

fn bits(data: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0][..], data].concat())
}

fn cert(host: &str) -> Vec<u8> {
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

pub fn mint(host: &str) -> Held {
    let der = cert(host);
    let mut roots = Roots::default();
    roots.add(&der).unwrap();
    Held {
        host: host.to_string(),
        der,
        roots,
        now: Time {
            year: 2027,
            month: 6,
            day: 15,
            hour: 12,
            minute: 0,
            second: 0,
        },
        protocol: None,
    }
}

fn offered(offer: &Offer) -> Result<Share, Error> {
    let mut found = None;
    for item in &offer.extensions {
        if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer)? {
            found = items.into_iter().next();
        }
    }
    found.ok_or(Error::Missing)
}

fn group(id: u16) -> Result<Group, Error> {
    match id {
        0x001d => Ok(Group::X25519),
        0x0017 => Ok(Group::Secp256r1),
        _ => Err(Error::Value),
    }
}

fn message(kind: Kind, body: Vec<u8>) -> Result<Vec<u8>, Error> {
    Message { kind, body }.write()
}

fn context(transcript: &[u8]) -> Vec<u8> {
    let mut data = vec![0x20; 64];
    data.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    data.push(0);
    data.extend_from_slice(transcript);
    data
}

fn absorb(digest: &mut Running, bytes: &[u8]) {
    digest.update(bytes);
}

pub struct Spoken {
    pub reply: Reply,
    pub hello: Vec<u8>,
    pub rest: Vec<u8>,
    pub waiting: Waiting,
    server: tls::Traffic,
}

pub fn spoken(
    hello: &Hello,
    held: &Held,
    secret: &[u8; 32],
    random: [u8; 32],
) -> Result<Spoken, Error> {
    let taken = offered(hello.offer())?;
    if !hello.offer().suites.contains(&0x1301) {
        return Err(Error::Suites);
    }
    let group = group(taken.group)?;
    let key = group.public(secret)?;
    let shared = group.agree(secret, &taken.key)?;
    let reply = Reply {
        random,
        session: hello.offer().session.clone(),
        suite: 0x1301,
        extensions: vec![
            Typed::Chosen(Share {
                group: taken.group,
                key,
            })
            .write()?,
            Typed::Version(0x0304).write()?,
        ],
    };
    let start = message(Kind::Reply, reply.write()?)?;
    let mut digest = Running::new(Hash::Sha256);
    digest.update(hello.spoken());
    digest.update(&start);
    let schedule = tls::Schedule::new(Hash::Sha256, &shared)?;
    let client = schedule.client(&digest.peek())?;
    let server = schedule.server(&digest.peek())?;
    let extra = match &held.protocol {
        Some(name) => vec![Typed::Protocols(vec![name.clone()]).write()?],
        None => Vec::new(),
    };
    let extensions = message(Kind::Extensions, Encrypted { extensions: extra }.write()?)?;
    absorb(&mut digest, &extensions);
    let certificate = message(
        Kind::Certificate,
        Chain {
            context: Vec::new(),
            entries: vec![Entry {
                cert: held.der.clone(),
                extensions: Vec::new(),
            }],
        }
        .write()?,
    )?;
    absorb(&mut digest, &certificate);
    let verify = message(
        Kind::Verify,
        Verify {
            algorithm: 0x0403,
            signature: signed(&held.host, &context(&digest.peek())),
        }
        .write()?,
    )?;
    absorb(&mut digest, &verify);
    let finished = message(
        Kind::Finished,
        Finished {
            data: server.finished(&digest.peek())?,
        }
        .write()?,
    )?;
    absorb(&mut digest, &finished);
    let mut rest = Vec::new();
    rest.extend_from_slice(&extensions);
    rest.extend_from_slice(&certificate);
    rest.extend_from_slice(&verify);
    rest.extend_from_slice(&finished);
    Ok(Spoken {
        reply,
        hello: start,
        rest,
        waiting: Waiting { digest, client },
        server,
    })
}

pub fn answer(
    hello: &Hello,
    held: &Held,
    secret: &[u8; 32],
    random: [u8; 32],
) -> Result<(Reply, Vec<Record>, Waiting), Error> {
    let spoken = spoken(hello, held, secret, random)?;
    let keys = spoken.server.keys(Aead::Aes128)?;
    let record = Layer::new(Aead::Aes128, &keys)?.protect(Content::Handshake, &spoken.rest, 0)?;
    Ok((spoken.reply, vec![record], spoken.waiting))
}

pub fn frame(content: Content, fragment: Vec<u8>) -> Record {
    Record {
        content,
        version: 0x0303,
        fragment,
    }
}
