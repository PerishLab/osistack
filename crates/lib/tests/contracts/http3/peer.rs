use crate::tls::{Held, mint, spoken};
use crypto::{Aead, Group, Hash};
use h3::{Call, Control, Decoder, Encoder, Event, Field, Request, Settings};
use quic::{Applied, Flight, Frame, Handshake, Header, Initial, Kind, Number, Short};
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tls::{Hello, Place, Schedule, Typed};

const LIMIT: usize = 1 << 16;
const SECRET: [u8; 32] = [8; 32];
const RANDOM: [u8; 32] = [5; 32];
const SERVER: [u8; 8] = [4; 8];

pub(crate) struct Peer {
    pub uri: String,
    pub roots: tls::x509::trust::Roots,
    done: Option<JoinHandle<()>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.join();
        }
    }
}

pub(crate) fn serve() -> Peer {
    let held = mint("localhost");
    let roots = held.roots.clone();
    let peer = socket();
    let port = peer.local_addr().unwrap().port();
    let uri = format!("https://localhost:{port}");
    let done = thread::spawn(move || drive(peer, held));
    Peer {
        uri,
        roots,
        done: Some(done),
    }
}

fn socket() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 2048];
    let (used, from) = socket.recv_from(&mut buf).unwrap();
    (buf[..used].to_vec(), from)
}

fn share(hello: &Hello) -> Vec<u8> {
    let mut found = None;
    for item in &hello.offer().extensions {
        if let Some(Typed::Shares(items)) = Typed::parse(item, Place::Offer).unwrap() {
            found = items.into_iter().next();
        }
    }
    found.unwrap().key
}

fn space(kind: Kind, dcid: &[u8], scid: &[u8]) -> Flight {
    Flight {
        kind,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: Vec::new(),
    }
}

fn pack(keys: &quic::Keys, dcid: &[u8], number: u64, payload: &[u8]) -> Vec<u8> {
    let written = Number::new(number, None).unwrap();
    let short = Short {
        spin: false,
        phase: false,
        dcid: dcid.to_vec(),
        offset: 0,
    };
    keys.protect(number, &short.write(&written).unwrap(), payload)
        .unwrap()
}

fn stream(id: u64, data: &[u8], fin: bool) -> Frame {
    Frame::Stream(quic::Stream {
        id,
        offset: 0,
        data: data.to_vec(),
        fin,
        sized: true,
    })
}

fn take(inbox: &mut Inbox, frame: Frame) {
    let Frame::Stream(quic::Stream { id, data, fin, .. }) = frame else {
        return;
    };
    if id == 2 {
        let rest = if !inbox.typed && data.first() == Some(&0x00) {
            inbox.typed = true;
            data[1..].to_vec()
        } else {
            data
        };
        let _ = inbox.control.feed(&rest);
        return;
    }
    if id != 0 {
        return;
    }
    for event in inbox.incoming.feed(&data).unwrap() {
        match event {
            Event::Headers(block) => inbox.got = Some(block),
            Event::Data(part) => inbox.body.extend(part),
            Event::End => inbox.ended = true,
            Event::Trailers(_) => {}
        }
    }
    if fin && inbox.incoming.end().unwrap() == Event::End {
        inbox.ended = true;
    }
}

fn headed(fields: &[Field], body: &[u8]) -> Vec<u8> {
    let mut reply = Request::new(LIMIT);
    let mut payload = reply.headers(&Encoder::new(true).encode(fields)).unwrap();
    if !body.is_empty() {
        payload.extend(reply.data(body).unwrap());
    }
    reply.finish().unwrap();
    payload
}

fn replied(body: &[u8]) -> Vec<u8> {
    headed(
        &[
            Field::new(b":status", b"200"),
            Field::new(b"content-type", b"text/plain"),
        ],
        body,
    )
}

fn drive(peer: UdpSocket, mut held: Held) {
    held.protocol = Some(b"h3".to_vec());
    let (packet, from) = recv(&peer);
    let Header::Long(long) = Header::parse(&packet, 0).unwrap() else {
        panic!("not long");
    };
    let size = long.size().unwrap();
    let opened = Initial::new(&long.dcid)
        .unwrap()
        .client
        .unprotect(&packet[..size], long.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { data, .. } = &frames[0] else {
        panic!("not crypto");
    };
    let offer = Hello::offered(data).unwrap();
    let spoken = spoken(&offer, &held, &SECRET, RANDOM).unwrap();
    let shared = Group::X25519.agree(&SECRET, &share(&offer)).unwrap();
    let accepted = offer.accept(&spoken.reply, &shared).unwrap();
    let initial = space(Kind::Initial, &long.scid, &SERVER);
    let start = initial
        .crypto(
            &Initial::new(&long.dcid).unwrap().server,
            0,
            &spoken.hello,
            0,
        )
        .unwrap();
    peer.send_to(&start, from).unwrap();
    let handshake = Handshake::new(
        Hash::Sha256,
        Aead::Aes128,
        accepted.client().secret(),
        accepted.server().secret(),
    )
    .unwrap();
    let rest = space(Kind::Handshake, &long.scid, &SERVER)
        .crypto(&handshake.server, 0, &spoken.rest, 0)
        .unwrap();
    peer.send_to(&rest, from).unwrap();
    let (packet, _) = recv(&peer);
    let Header::Long(header) = Header::parse(&packet, SERVER.len()).unwrap() else {
        panic!("not long");
    };
    let opened = handshake
        .client
        .unprotect(&packet, header.offset, None)
        .unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Crypto { data, .. } = &frames[0] else {
        panic!("not crypto");
    };
    spoken.waiting.check(data).unwrap();
    let schedule = Schedule::new(Hash::Sha256, &shared).unwrap();
    let master = schedule.master().unwrap();
    let transcript = spoken.waiting.digest();
    let applied = Applied::new(
        Hash::Sha256,
        Aead::Aes128,
        master.client(&transcript).unwrap().secret(),
        master.server(&transcript).unwrap().secret(),
    )
    .unwrap();
    reply(&Link {
        peer: &peer,
        from,
        applied,
        local: long.scid.len(),
        dcid: long.scid,
    });
}

struct Link<'a> {
    peer: &'a UdpSocket,
    from: SocketAddr,
    applied: Applied,
    local: usize,
    dcid: Vec<u8>,
}

struct Inbox {
    incoming: Request,
    control: Control,
    got: Option<Vec<u8>>,
    body: Vec<u8>,
    ended: bool,
    typed: bool,
}

fn reply(link: &Link<'_>) {
    let mut inbox = Inbox {
        incoming: Request::new(LIMIT),
        control: Control::new(LIMIT),
        got: None,
        body: Vec::new(),
        ended: false,
        typed: false,
    };
    while !inbox.ended {
        let (packet, _) = recv(link.peer);
        let opened = link
            .applied
            .client
            .unprotect(&packet, 1 + link.local, None)
            .unwrap();
        for frame in Frame::all(&opened.payload).unwrap() {
            take(&mut inbox, frame);
        }
    }
    let fields = Decoder::new(0).decode(&inbox.got.unwrap()).unwrap();
    let path = fields
        .iter()
        .find(|field| field.name == b":path")
        .map(|field| field.value.as_slice())
        .unwrap_or(b"/");
    let method = fields
        .iter()
        .find(|field| field.name == b":method")
        .map(|field| field.value.as_slice())
        .unwrap_or(b"GET");
    let payload = if method == b"POST" {
        replied(&inbox.body)
    } else if path == b"/hello" {
        replied(b"hello")
    } else {
        replied(b"ok")
    };
    let settings = Call::control(&Settings::default()).unwrap();
    let frames = [stream(3, &settings, false), stream(0, &payload, true)];
    let packet = pack(
        &link.applied.server,
        &link.dcid,
        0,
        &Frame::join(&frames).unwrap(),
    );
    link.peer.send_to(&packet, link.from).unwrap();
}
