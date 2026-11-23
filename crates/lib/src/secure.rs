use crate::client::Client;
use crate::error::Error;
use crypto::{Aead, Group};
use socket::Stream;
use std::io::Read;
use std::time::{Duration, Instant, SystemTime};
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
}

impl Link {
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
                _ => return Err(Error::Tls(tls::Error::Kind)),
            }
        }
    }
}

pub fn open(stream: Stream, host: &str, client: &Client, deadline: Instant) -> Result<Link, Error> {
    let write = budget(deadline, client.write)?;
    let read = budget(deadline, client.read)?;
    let secret = entropy()?;
    let random = entropy()?;
    let share = Share {
        group: 0x001d,
        key: Group::X25519.public(&secret).map_err(tls::Error::from)?,
    };
    let hello = Hello::start(host.as_bytes(), &[b"http/1.1".to_vec()], share, random)?;
    let mut stream = stream;
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
    let shared = agreed(&secret, &reply)?;
    let accepted = hello.accept(&reply, &shared)?;
    let mut pipe = Pipe {
        stream: &mut stream,
        inbox: &mut inbox,
        timeout: read,
    };
    let verified = flight(&mut pipe, &accepted, host, &client.roots)?;
    let complete = verified.finish()?;
    let aead = aead(accepted.reply().suite)?;
    let keys = accepted.client().keys(aead)?;
    let mut held = Layer::new(aead, &keys)?;
    let record = held.protect(Content::Handshake, complete.spoken(), 0)?;
    push(&mut stream, &record, write)?;
    Ok(Link {
        stream,
        inbox,
        plain: Vec::new(),
        send: cover(aead, complete.client())?,
        recv: cover(aead, complete.server())?,
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

fn agreed(secret: &[u8; 32], reply: &Reply) -> Result<Vec<u8>, Error> {
    let mut share = None;
    for item in &reply.extensions {
        if let Some(Typed::Chosen(found)) = Typed::parse(item, Place::Reply)? {
            share = Some(found);
        }
    }
    let share = share.ok_or(tls::Error::Missing)?;
    let group = match share.group {
        0x001d => Group::X25519,
        0x0017 => Group::Secp256r1,
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
        records.push(take(pipe.stream, pipe.inbox, pipe.timeout)?);
        if packed(accepted, &records)? {
            return Ok(accepted.verify(host, roots, clock(), &records)?);
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

fn entropy() -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut out))
        .map_err(|_| Error::Random)?;
    Ok(out)
}

fn budget(deadline: Instant, phase: Duration) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| *left > Duration::ZERO)
        .map(|left| left.min(phase))
        .ok_or(Error::Timeout)
}

fn leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days(year: u32, month: u32) -> u64 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn clock() -> Time {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|span| span.as_secs())
        .unwrap_or(0);
    let second = (secs % 60) as u8;
    let minutes = secs / 60;
    let minute = (minutes % 60) as u8;
    let hours = minutes / 60;
    let hour = (hours % 24) as u8;
    let mut day = hours / 24;
    let mut year = 1970u32;
    loop {
        let length = if leap(year) { 366u64 } else { 365u64 };
        if day < length {
            break;
        }
        day -= length;
        year += 1;
    }
    let mut month = 1u32;
    loop {
        let length = days(year, month);
        if day < length {
            break;
        }
        day -= length;
        month += 1;
    }
    Time {
        year: year as u16,
        month: month as u8,
        day: (day + 1) as u8,
        hour,
        minute,
        second,
    }
}
