use crate::error::Error;
use crypto::{Aead, Group, Hash};
use http::Uri;
use quic::{
    Applied, Direction, Flight, Handshake, Header, Hearing, Kind, Opening, Param, Params, Side,
};
use socket::Datagram;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use tls::x509::Time;
use tls::{
    Accepted, Complete, Extension, Hello, Kind as Form, Message, Place, Reply, Share, Typed,
};

pub(crate) struct Wire {
    sock: Datagram,
    dest: SocketAddr,
    deadline: Instant,
    write: Duration,
}

pub(crate) struct Session {
    pub wire: Wire,
    pub applied: Applied,
    pub scid: Vec<u8>,
    pub dcid: Vec<u8>,
    pub sent: u64,
    pub read: Duration,
}

struct Early {
    hello: Hello,
    secret: [u8; 32],
    scid: Vec<u8>,
    hearing: Hearing,
    handshake: Option<Handshake>,
    accepted: Option<Accepted>,
    complete: Option<Complete>,
    remote: Vec<u8>,
    host: String,
}

pub(crate) fn start(clock: &super::Clock, uri: &Uri) -> Result<Session, Error> {
    let dest = locate(clock, uri)?;
    let sock = Datagram::bind(SocketAddr::from(([0, 0, 0, 0], 0)))?;
    let secret = entropy()?;
    let random = entropy()?;
    let scid = entropy()?[..8].to_vec();
    let original = entropy()?[..8].to_vec();
    let public = Group::X25519.public(&secret).map_err(tls::Error::from)?;
    let share = Share {
        group: 0x001d,
        key: public,
    };
    let hello = Hello::begin(uri.host().as_bytes(), &[b"h3".to_vec()], &[share], random)?;
    let hello = offered(hello, &scid)?;
    let packet = Opening {
        dcid: original.clone(),
        scid: scid.clone(),
        token: Vec::new(),
    }
    .write(hello.spoken())?;
    let wire = Wire {
        sock,
        dest,
        deadline: clock.deadline,
        write: clock.client.write,
    };
    emit(&wire, &packet)?;
    let mut early = Early {
        hello,
        secret,
        scid: scid.clone(),
        hearing: Hearing::new(&original, scid.len())?,
        handshake: None,
        accepted: None,
        complete: None,
        remote: Vec::new(),
        host: uri.host().to_owned(),
    };
    while early.complete.is_none() {
        let datagram = wait(&wire, clock.client.read)?;
        for packet in peel(&datagram, early.scid.len())? {
            ingest(&mut early, &packet, &clock.client.roots)?;
        }
    }
    let complete = early.complete.as_ref().ok_or(Error::Short)?;
    if early.remote.is_empty() {
        return Err(Error::Short);
    }
    let handshake = early.handshake.as_ref().ok_or(Error::Short)?;
    let back = Flight {
        kind: Kind::Handshake,
        dcid: early.remote.clone(),
        scid: early.scid.clone(),
        token: Vec::new(),
    };
    emit(
        &wire,
        &back.crypto(&handshake.client, 0, complete.spoken(), 0)?,
    )?;
    Ok(Session {
        wire,
        applied: Applied::new(
            Hash::Sha256,
            Aead::Aes128,
            complete.client().secret(),
            complete.server().secret(),
        )?,
        scid,
        dcid: early.remote,
        sent: 0,
        read: clock.client.read,
    })
}

fn offered(hello: Hello, scid: &[u8]) -> Result<Hello, Error> {
    let mut offer = hello.offer().clone();
    let params = Params {
        list: vec![
            Param::Idle(30_000),
            Param::Source(scid.to_vec()),
            Param::Data(1 << 20),
            Param::Window(Side::Local, 1 << 16),
            Param::Window(Side::Remote, 1 << 16),
            Param::Window(Side::Uni, 1 << 16),
            Param::Streams(Direction::Bidi, 16),
            Param::Streams(Direction::Uni, 16),
        ],
    };
    offer.extensions.push(Extension {
        kind: 0x39,
        data: params.write()?,
    });
    let message = Message {
        kind: Form::Offer,
        body: offer.write()?,
    };
    Ok(Hello::offered(&message.write()?)?)
}

fn ingest(early: &mut Early, packet: &[u8], roots: &tls::x509::trust::Roots) -> Result<(), Error> {
    match Header::parse(packet, early.scid.len())? {
        Header::Long(long) => {
            if early.remote.is_empty() {
                early.remote = long.scid.clone();
            }
            match long.kind {
                Kind::Initial => opened(early, packet, roots),
                Kind::Handshake => finish(early, packet, roots),
            }
        }
        Header::Retry(_) | Header::Negotiation(_) => Err(Error::Usage),
        Header::Short(_) => Ok(()),
    }
}

fn opened(early: &mut Early, packet: &[u8], roots: &tls::x509::trust::Roots) -> Result<(), Error> {
    early.hearing.ingest(packet)?;
    if early.accepted.is_some() {
        return Ok(());
    }
    let Some((message, used)) = Message::parse(early.hearing.crypto(), (1 << 24) - 1)? else {
        return Ok(());
    };
    if used != early.hearing.crypto().len() || message.kind != Form::Reply {
        return Ok(());
    }
    let reply = Reply::parse(&message.body)?;
    let shared = Group::X25519
        .agree(&early.secret, &chosen(&reply)?)
        .map_err(tls::Error::from)?;
    let accepted = early.hello.accept(&reply, &shared)?;
    early.handshake = Some(Handshake::new(
        Hash::Sha256,
        Aead::Aes128,
        accepted.client().secret(),
        accepted.server().secret(),
    )?);
    early.accepted = Some(accepted);
    settle(early, roots)
}

fn finish(early: &mut Early, packet: &[u8], roots: &tls::x509::trust::Roots) -> Result<(), Error> {
    let Some(handshake) = early.handshake.as_mut() else {
        return Err(Error::Usage);
    };
    handshake.ingest(packet, early.scid.len())?;
    settle(early, roots)
}

fn settle(held: &mut Early, roots: &tls::x509::trust::Roots) -> Result<(), Error> {
    if held.complete.is_some() {
        return Ok(());
    }
    let Some(accepted) = held.accepted.as_ref() else {
        return Ok(());
    };
    let Some(handshake) = held.handshake.as_ref() else {
        return Ok(());
    };
    match accepted.checked(&held.host, roots, Time::now(), handshake.crypto()) {
        Ok(verified) => {
            if verified.protocol() != Some(b"h3".as_slice()) {
                return Err(Error::Http3);
            }
            held.complete = Some(verified.finish()?);
            Ok(())
        }
        Err(tls::Error::Length) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn chosen(reply: &Reply) -> Result<Vec<u8>, Error> {
    for item in &reply.extensions {
        if let Some(Typed::Chosen(share)) = Typed::parse(item, Place::Reply)? {
            return Ok(share.key);
        }
    }
    Err(Error::Tls(tls::Error::Missing))
}

fn peel(buffer: &[u8], local: usize) -> Result<Vec<Vec<u8>>, Error> {
    let mut rest = buffer;
    let mut out = Vec::new();
    while !rest.is_empty() {
        match Header::parse(rest, local)? {
            Header::Long(long) => {
                let size = long.size()?;
                let packet = rest.get(..size).ok_or(Error::Short)?;
                out.push(packet.to_vec());
                rest = &rest[size..];
            }
            Header::Retry(_) | Header::Negotiation(_) | Header::Short(_) => {
                out.push(rest.to_vec());
                break;
            }
        }
    }
    Ok(out)
}

fn entropy() -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut out))
        .map_err(|_| Error::Random)?;
    Ok(out)
}

pub(crate) fn budget(deadline: Instant, phase: Duration) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| *left > Duration::ZERO)
        .map(|left| left.min(phase))
        .ok_or(Error::Timeout)
}

fn locate(clock: &super::Clock, uri: &Uri) -> Result<SocketAddr, Error> {
    let pair = clock.client.offered(uri.host(), uri.port());
    let (host, port) = match (clock.client.http3, pair) {
        (crate::client::Http3::Only, _) | (_, None) => (uri.host().to_owned(), uri.port()),
        (_, Some(pair)) => pair,
    };
    resolve(&host, port)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, Error> {
    let found: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(socket::Error::Resolve)?
        .collect();
    found
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| found.first().copied())
        .ok_or(Error::Socket(socket::Error::Empty))
}

pub(crate) fn wait(wire: &Wire, phase: Duration) -> Result<Vec<u8>, Error> {
    let mut buf = [0u8; 2048];
    let timeout = budget(wire.deadline, phase)?;
    match wire.sock.recv(&mut buf, Some(timeout)) {
        Ok((used, _)) => Ok(buf[..used].to_vec()),
        Err(socket::Error::Timeout(_)) => Err(Error::Timeout),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn emit(wire: &Wire, bytes: &[u8]) -> Result<(), Error> {
    let timeout = budget(wire.deadline, wire.write)?;
    match wire.sock.send(bytes, wire.dest, Some(timeout)) {
        Ok(_) => Ok(()),
        Err(socket::Error::Timeout(_)) => Err(Error::Timeout),
        Err(error) => Err(error.into()),
    }
}
