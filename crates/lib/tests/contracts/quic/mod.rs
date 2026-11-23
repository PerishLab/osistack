mod ecn;
mod integrity;
mod protect;
mod update;

use crate::behaviour::Check;
use crate::{flow, reno};
use quic::{
    Amplify, Client, Echo, Error, Fault, Frame, Header, Issued, Path, Peers, Refused, Validity,
    Verdict, answer,
};

pub fn table() -> Vec<(&'static str, Check)> {
    let mut rows = vec![
        ("path-validation", path as Check),
        ("version-negotiation", version as Check),
        ("connection-id", ident as Check),
    ];
    rows.extend(ecn::table());
    rows.extend(protect::table());
    rows.extend(update::table());
    rows.extend(integrity::table());
    rows.extend(flow::table());
    rows.extend(reno::table());
    rows
}

pub fn wire(frames: &[Frame]) -> Vec<Frame> {
    Frame::all(&Frame::join(frames).unwrap()).unwrap()
}

fn token(seed: u8) -> [u8; 8] {
    [seed; 8]
}

fn probe(path: &mut Path, now: u64, seed: u8, room: u64) -> Vec<Frame> {
    let sent = path.challenge(now, token(seed), room).unwrap();
    let mut frames = vec![Frame::Challenge(sent.token)];
    if sent.expand {
        frames.push(Frame::Padding(1191));
    }
    wire(&frames)
}

fn answered(echo: &mut Echo, frames: &[Frame], room: u64) -> Vec<Frame> {
    for frame in frames {
        if let Frame::Challenge(found) = frame {
            assert!(echo.challenge(*found));
        }
    }
    let sent = echo.next(room).unwrap();
    assert_eq!(sent.expand, room >= 1200);
    let mut back = vec![Frame::Response(sent.token)];
    if sent.expand {
        back.push(Frame::Padding(1191));
    }
    wire(&back)
}

fn confirmed(path: &mut Path, frames: &[Frame]) -> bool {
    let mut found = false;
    for frame in frames {
        if let Frame::Response(seen) = frame {
            found |= path.response(*seen);
        }
    }
    found
}

fn path() {
    let mut near = Path::new(0);
    let mut far = Echo::default();
    let frames = probe(&mut near, 0, 1, 1200);
    assert_eq!(frames[0], Frame::Challenge(token(1)));
    assert_eq!(near.validity(), Validity::Pending);
    let back = answered(&mut far, &frames, 1200);
    assert!(confirmed(&mut near, &back));
    assert_eq!(near.validity(), Validity::Valid);
    assert!(near.mtu());
    assert_eq!(near.deadline(), None);
    let mut small = Path::new(0);
    let frames = probe(&mut small, 0, 2, 1199);
    assert_eq!(frames, vec![Frame::Challenge(token(2))]);
    assert!(confirmed(&mut small, &answered(&mut far, &frames, 1199)));
    assert!(!small.mtu());
    assert_eq!(Path::new(0).timeout(), 2_997_000);
    assert_eq!(Path::new(5_000_000).timeout(), 15_000_000);
    let mut idle = Path::new(0);
    assert!(!idle.response(token(1)));
    probe(&mut idle, 0, 3, 1200);
    assert!(!idle.response(token(9)));
    assert_eq!(idle.validity(), Validity::Pending);
    let again = idle.challenge(0, token(3), 1200);
    assert!(matches!(again, Err(Error::Duplicate)));
    let timeout = idle.timeout();
    assert!(!idle.expire(timeout - 1));
    assert!(idle.expire(timeout));
    assert_eq!(idle.validity(), Validity::Failed);
    assert!(!idle.response(token(3)));
    assert!(idle.challenge(timeout, token(4), 1200).is_err());
    let mut crowd = Path::new(0);
    for seed in 0..8 {
        probe(&mut crowd, 0, seed, 1200);
    }
    assert!(crowd.challenge(0, token(8), 1200).is_err());
    crowd.abandon();
    assert_eq!(crowd.validity(), Validity::Failed);
    assert!(far.challenge(token(0)));
    assert!(far.challenge(token(1)));
    assert_eq!(far.next(0), None);
    assert_eq!(far.pending(), 2);
    assert_eq!(far.next(1).unwrap().token, token(0));
    assert_eq!(far.next(1).unwrap().token, token(1));
    for seed in 0..8 {
        assert!(far.challenge(token(seed)));
    }
    assert!(!far.challenge(token(8)));
    assert_eq!(far.pending(), 8);
    shield();
}

fn shield() {
    let mut server = Amplify::new(false);
    server.receive(1200);
    assert_eq!(server.room(), 3600);
    assert!(server.send(3600));
    assert!(server.blocked());
    assert!(!server.send(1));
    server.receive(100);
    assert_eq!(server.room(), 300);
    assert!(!server.send(301));
    assert!(server.send(300));
    let mut near = Path::new(0);
    let mut client = Echo::default();
    let frames = probe(&mut near, 0, 5, server.room().max(1200));
    let back = answered(&mut client, &frames, 1200);
    assert!(confirmed(&mut near, &back));
    server.validate();
    assert!(server.validated());
    assert!(server.send(1 << 20));
    assert_eq!(server.room(), u64::MAX);
    assert_eq!(Amplify::new(true).room(), u64::MAX);
    assert!(!Amplify::new(false).send(1));
    assert!(Amplify::new(true).send(1 << 20));
}

fn initial(version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0];
    out.extend(version.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend(dcid);
    out.push(scid.len() as u8);
    out.extend(scid);
    out.resize(1200, 0);
    out
}

fn version() {
    const THEIRS: u32 = 0xff00_0020;
    const GREASE: u32 = 0x1a2a_3a4a;
    let (dcid, scid) = ([1u8; 8], [2u8; 4]);
    let datagram = initial(THEIRS, &dcid, &scid);
    assert!(matches!(Header::parse(&datagram, 8), Err(Error::Version)));
    let reply = answer(&datagram, &[1], GREASE).unwrap().unwrap();
    assert_eq!((&reply.dcid[..], &reply.scid[..]), (&scid[..], &dcid[..]));
    assert_eq!(reply.versions, vec![1, GREASE]);
    let bytes = reply.write().unwrap();
    let Header::Negotiation(seen) = Header::parse(&bytes, 4).unwrap() else {
        panic!("not a negotiation packet");
    };
    assert_eq!(seen, reply);
    let mut client = Client::new(THEIRS, &dcid, &scid);
    assert_eq!(client.receive(&seen), Verdict::Abandon);
    assert_eq!(client.receive(&seen), Verdict::Ignore);
    let mut wrong = Client::new(THEIRS, &dcid, &[9]);
    assert_eq!(wrong.receive(&seen), Verdict::Ignore);
    let mut other = Client::new(THEIRS, &[7; 8], &scid);
    assert_eq!(other.receive(&seen), Verdict::Ignore);
    let mut late = Client::new(THEIRS, &dcid, &scid);
    late.processed();
    assert_eq!(late.receive(&seen), Verdict::Ignore);
    let mut known = Client::new(1, &dcid, &scid);
    assert_eq!(known.receive(&seen), Verdict::Ignore);
    let both = answer(&datagram, &[1, GREASE], GREASE).unwrap().unwrap();
    assert_eq!(both.versions, vec![1, GREASE]);
    assert_eq!(bytes[0] & 0x80, 0x80);
    assert_eq!(bytes[1..5], [0, 0, 0, 0]);
    let cut = Header::parse(&bytes[..bytes.len() - 1], 4);
    assert!(matches!(cut, Err(Error::Versions)));
    let plain = answer(&datagram, &[1], 0x1234_5678).unwrap().unwrap();
    assert_eq!(plain.versions, vec![1]);
    let ours = initial(1, &dcid, &scid);
    assert_eq!(answer(&ours, &[1], GREASE).unwrap(), None);
    let short = &datagram[..1199];
    assert_eq!(answer(short, &[1], GREASE).unwrap(), None);
    let zero = initial(0, &dcid, &scid);
    assert_eq!(answer(&zero, &[1], GREASE).unwrap(), None);
    let mut local = datagram.clone();
    local[0] = 0x40;
    assert_eq!(answer(&local, &[1], GREASE).unwrap(), None);
}

fn cid(seed: u8) -> Vec<u8> {
    vec![seed; 8]
}

fn secret(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn issued(near: &mut Issued, far: &mut Peers, seed: u8, retire: u64) -> Result<Vec<u64>, Fault> {
    let frame = near.issue(cid(seed), secret(seed), retire).unwrap();
    let Frame::Issue {
        sequence,
        retire,
        cid,
        token,
    } = wire(&[frame]).remove(0)
    else {
        panic!("not an issue frame");
    };
    far.receive(sequence, retire, &cid, token)
}

fn retired(near: &mut Issued, number: u64, dcid: &[u8]) -> Result<bool, Fault> {
    let Frame::Retire(sequence) = wire(&[Frame::Retire(number)]).remove(0) else {
        panic!("not a retire frame");
    };
    near.retire(sequence, dcid)
}

fn ident() {
    let mut near = Issued::new(cid(0), 4);
    let mut far = Peers::new(cid(0), Some(secret(0)), 4);
    assert_eq!(issued(&mut near, &mut far, 1, 0), Ok(vec![]));
    assert_eq!(issued(&mut near, &mut far, 2, 0), Ok(vec![]));
    assert_eq!(far.live(), vec![0, 1, 2]);
    assert!(far.matches(&secret(0)));
    assert!(!far.matches(&secret(1)));
    assert_eq!(far.rotate(), Some(0));
    assert_eq!(far.current(), (1, &cid(1)[..]));
    assert!(far.matches(&secret(1)));
    assert_eq!(retired(&mut near, 0, &cid(1)), Ok(true));
    assert_eq!(retired(&mut near, 0, &cid(1)), Ok(false));
    assert_eq!(near.live(), vec![1, 2]);
    assert_eq!(issued(&mut near, &mut far, 3, 2), Ok(vec![1]));
    assert_eq!(near.active(), 2);
    assert_eq!(far.receive(1, 0, &cid(1), secret(1)), Ok(vec![]));
    assert_eq!(far.live(), vec![2, 3]);
    assert_eq!(far.current(), (2, &cid(2)[..]));
    assert_eq!(retired(&mut near, 1, &cid(2)), Ok(true));
    assert_eq!(near.live(), vec![2, 3]);
    assert_eq!(near.find(&cid(3)), Some(3));
    assert_eq!(retired(&mut near, 2, &cid(2)), Err(Fault::Protocol));
    assert_eq!(retired(&mut near, 9, &cid(3)), Err(Fault::Protocol));
    let Frame::Issue { retire, .. } = near.issue(cid(4), secret(4), 0).unwrap() else {
        panic!("not an issue frame");
    };
    assert_eq!(retire, 2);
    assert_eq!(far.receive(4, 2, &cid(4), secret(4)), Ok(vec![]));
    assert_eq!(issued(&mut near, &mut far, 5, 0), Ok(vec![]));
    assert_eq!(retired(&mut near, 6, &cid(3)), Err(Fault::Protocol));
    assert_eq!(near.active(), 4);
    assert_eq!(far.active(), 4);
    let frame = near.issue(cid(6), secret(6), 0);
    assert_eq!(frame.unwrap_err(), Refused);
    assert_eq!(far.receive(8, 0, &cid(8), secret(8)), Err(Fault::Ids));
    assert_eq!(far.active(), 4);
    assert_eq!(far.receive(3, 0, &cid(3), secret(3)), Ok(vec![]));
    assert_eq!(far.receive(3, 0, &cid(9), secret(3)), Err(Fault::Protocol));
    assert_eq!(far.receive(8, 0, &cid(2), secret(8)), Err(Fault::Protocol));
    assert_eq!(far.receive(8, 9, &cid(8), secret(8)), Err(Fault::Encoding));
    let long = vec![8; 21];
    assert_eq!(far.receive(8, 0, &long, secret(8)), Err(Fault::Encoding));
    let mut wide = Issued::new(cid(0), 8);
    assert!(wide.issue(vec![1; 20], secret(1), 0).is_ok());
    assert_eq!(wide.issue(vec![], secret(2), 0).unwrap_err(), Refused);
    assert_eq!(wide.issue(vec![1; 21], secret(2), 0).unwrap_err(), Refused);
    assert_eq!(wide.issue(vec![1; 20], secret(2), 0).unwrap_err(), Refused);
    let mut tight = Issued::new(cid(0), 3);
    assert!(tight.issue(cid(1), secret(1), 0).is_ok());
    assert!(tight.issue(cid(2), secret(2), 0).is_ok());
    assert!(tight.issue(cid(3), secret(3), 0).is_err());
    assert!(tight.issue(cid(3), secret(3), 3).is_ok());
    let mut zero = Issued::new(Vec::new(), 4);
    assert_eq!(zero.issue(cid(1), secret(1), 0).unwrap_err(), Refused);
    assert_eq!(zero.retire(0, &[1]), Err(Fault::Protocol));
    let mut only = Peers::new(Vec::new(), None, 4);
    assert_eq!(only.receive(1, 0, &cid(1), secret(1)), Err(Fault::Protocol));
    let mut next = Peers::new(cid(0), Some(secret(0)), 4);
    assert_eq!(next.receive(1, 1, &cid(1), secret(1)), Ok(vec![0]));
    assert_eq!(far.receive(3, 0, &cid(3), secret(9)), Err(Fault::Protocol));
}
