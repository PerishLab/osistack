use crate::client::{Client, entropy};
use crate::error::Error;
use crypto::{Aead, Group};
use socket::Stream;
use std::time::{Duration, Instant};
use tls::x509::Time;
use tls::x509::trust::Roots;
use tls::{Accepted, Content, Hello, Kind, Layer, Message, Place, Record, Reply, Share, Typed};

const INNER: usize = 16384;

struct Pipe<'a> {
    stream: &'a mut Stream,
    inbox: &'a mut Vec<u8>,
    timeout: Duration,
}

pub struct Link {
    stream: Stream,
    inbox: Vec<u8>,
    plain: Vec<u8>,
    send: Layer,
    recv: Layer,
    h2: bool,
}

impl Link {
    pub fn h2(&self) -> bool {
        self.h2
    }

    pub fn write(&mut self, bytes: &[u8], timeout: Duration) -> Result<usize, Error> {
        let mut sent = 0;
        while sent < bytes.len() {
            let end = (sent + INNER).min(bytes.len());
            let record = self
                .send
                .protect(Content::Application, &bytes[sent..end], 0)?;
            push(&mut self.stream, &record, timeout)?;
            sent = end;
        }
        Ok(sent)
    }

    pub fn read(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Error> {
        if self.plain.is_empty() {
            self.pull(timeout)?;
        }
        let count = buf.len().min(self.plain.len());
        buf[..count].copy_from_slice(&self.plain[..count]);
        self.plain.drain(..count);
        Ok(count)
    }

    fn pull(&mut self, timeout: Duration) -> Result<(), Error> {
        loop {
            let record = take(&mut self.stream, &mut self.inbox, timeout)?;
            let opened = self.recv.unprotect(&record)?;
            match opened.content {
                Content::Application => {
                    self.plain.extend(opened.payload);
                    return Ok(());
                }
                Content::Handshake => continue,
                Content::Alert if opened.payload == [1, 0] => return Ok(()),
                _ => return Err(Error::Tls(tls::Error::Kind)),
            }
        }
    }
}

pub fn open(stream: Stream, host: &str, client: &Client, deadline: Instant) -> Result<Link, Error> {
    begin(
        held(stream, host, client, deadline),
        &[b"http/1.1".to_vec()],
    )
}

pub fn browse(
    stream: Stream,
    host: &str,
    client: &Client,
    deadline: Instant,
) -> Result<Link, Error> {
    begin(
        held(stream, host, client, deadline),
        &[b"h2".to_vec(), b"http/1.1".to_vec()],
    )
}

fn held<'a>(stream: Stream, host: &'a str, client: &'a Client, deadline: Instant) -> Held<'a> {
    Held {
        stream,
        host,
        client,
        deadline,
    }
}

struct Held<'a> {
    stream: Stream,
    host: &'a str,
    client: &'a Client,
    deadline: Instant,
}

fn begin(held: Held, protocols: &[Vec<u8>]) -> Result<Link, Error> {
    let write = budget(held.deadline, held.client.write)?;
    let read = budget(held.deadline, held.client.read)?;
    let one = entropy()?;
    let two = entropy()?;
    let random = entropy()?;
    let shares = [
        Share {
            group: 0x001d,
            key: Group::X25519.public(&one).map_err(tls::Error::from)?,
        },
        Share {
            group: 0x0017,
            key: Group::Secp256r1.public(&two).map_err(tls::Error::from)?,
        },
    ];
    let hello = Hello::begin(held.host.as_bytes(), protocols, &shares, random)?;
    let mut stream = held.stream;
    let host = held.host;
    let client = held.client;
    let mut inbox = Vec::new();
    push(
        &mut stream,
        &frame(Content::Handshake, hello.spoken()),
        write,
    )?;
    let first = take(&mut stream, &mut inbox, read)?;
    if first.content != Content::Handshake {
        return Err(Error::Tls(tls::Error::Kind));
    }
    let reply = Reply::parse(&body(&first)?)?;
    if reply.retry() {
        return Err(Error::Tls(tls::Error::Kind));
    }
    let shared = agreed(&one, &two, &reply)?;
    let accepted = hello.accept(&reply, &shared)?;
    let mut pipe = Pipe {
        stream: &mut stream,
        inbox: &mut inbox,
        timeout: read,
    };
    let verified = flight(&mut pipe, &accepted, host, &client.roots)?;
    let h2 = verified.protocol() == Some(b"h2");
    let complete = verified.finish()?;
    let aead = aead(accepted.reply().suite)?;
    let keys = accepted.client().keys(aead)?;
    let mut layer = Layer::new(aead, &keys)?;
    let record = layer.protect(Content::Handshake, complete.spoken(), 0)?;
    push(&mut stream, &record, write)?;
    Ok(Link {
        stream,
        inbox,
        plain: Vec::new(),
        send: cover(aead, complete.client())?,
        recv: cover(aead, complete.server())?,
        h2,
    })
}

fn cover(aead: Aead, traffic: &tls::Traffic) -> Result<Layer, Error> {
    Ok(Layer::new(aead, &traffic.keys(aead)?)?)
}

fn aead(suite: u16) -> Result<Aead, Error> {
    match suite {
        0x1301 => Ok(Aead::Aes128),
        0x1302 => Ok(Aead::Aes256),
        0x1303 => Ok(Aead::Chacha),
        _ => Err(Error::Tls(tls::Error::Suites)),
    }
}

fn agreed(one: &[u8; 32], two: &[u8; 32], reply: &Reply) -> Result<Vec<u8>, Error> {
    let mut share = None;
    for item in &reply.extensions {
        if let Some(Typed::Chosen(found)) = Typed::parse(item, Place::Reply)? {
            share = Some(found);
        }
    }
    let share = share.ok_or(tls::Error::Missing)?;
    let (group, secret) = match share.group {
        0x001d => (Group::X25519, one),
        0x0017 => (Group::Secp256r1, two),
        _ => return Err(Error::Tls(tls::Error::Value)),
    };
    Ok(group.agree(secret, &share.key).map_err(tls::Error::from)?)
}

fn flight(
    pipe: &mut Pipe,
    accepted: &Accepted,
    host: &str,
    roots: &Roots,
) -> Result<tls::Verified, Error> {
    let mut records = Vec::new();
    loop {
        let record = take(pipe.stream, pipe.inbox, pipe.timeout)?;
        if record.content == Content::Change {
            continue;
        }
        records.push(record);
        if packed(accepted, &records)? {
            return Ok(accepted.verify(host, roots, Time::now(), &records)?);
        }
        if records.len() > 16 {
            return Err(Error::Tls(tls::Error::Length));
        }
    }
}

fn packed(accepted: &Accepted, records: &[Record]) -> Result<bool, Error> {
    let aead = aead(accepted.reply().suite)?;
    let mut layer = Layer::new(aead, &accepted.server().keys(aead)?)?;
    let mut payload = Vec::new();
    for record in records {
        let opened = layer.unprotect(record)?;
        if opened.content != Content::Handshake {
            return Err(Error::Tls(tls::Error::Kind));
        }
        payload.extend(opened.payload);
    }
    let mut data = payload.as_slice();
    let mut last = None;
    while !data.is_empty() {
        let Some((message, used)) = Message::parse(data, (1 << 24) - 1)? else {
            return Ok(false);
        };
        last = Some(message.kind);
        data = &data[used..];
    }
    Ok(last == Some(Kind::Finished))
}

fn body(record: &Record) -> Result<Vec<u8>, Error> {
    let (message, used) =
        Message::parse(&record.fragment, (1 << 24) - 1)?.ok_or(tls::Error::Length)?;
    if used != record.fragment.len() || message.kind != Kind::Reply {
        return Err(Error::Tls(tls::Error::Kind));
    }
    Ok(message.body)
}

fn frame(content: Content, fragment: &[u8]) -> Record {
    Record {
        content,
        version: 0x0303,
        fragment: fragment.to_vec(),
    }
}

fn push(stream: &mut Stream, record: &Record, timeout: Duration) -> Result<(), Error> {
    let bytes = record.write()?;
    let mut sent = 0;
    while sent < bytes.len() {
        let count = stream.write(&bytes[sent..], Some(timeout))?;
        if count == 0 {
            return Err(Error::Short);
        }
        sent += count;
    }
    Ok(())
}

fn take(stream: &mut Stream, inbox: &mut Vec<u8>, timeout: Duration) -> Result<Record, Error> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some((record, used)) = Record::parse(inbox)? {
            inbox.drain(..used);
            return Ok(record);
        }
        let count = stream.read(&mut chunk, Some(timeout))?;
        if count == 0 {
            return Err(Error::Short);
        }
        inbox.extend_from_slice(&chunk[..count]);
    }
}

fn budget(deadline: Instant, phase: Duration) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| *left > Duration::ZERO)
        .map(|left| left.min(phase))
        .ok_or(Error::Timeout)
}
