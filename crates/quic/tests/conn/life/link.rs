use quic::{
    Client, Frame, GRANULARITY, Header, Idle, Life, Mode, Negotiation, Peers, Rtt, Verdict, answer,
    stateless,
};

fn pto(rtt: &Rtt) -> u64 {
    rtt.smooth() + (4 * rtt.vary()).max(GRANULARITY)
}

fn shut() -> Frame {
    Frame::Application {
        code: 42,
        reason: b"done".to_vec(),
    }
}

fn wire(frame: &Frame) -> Vec<u8> {
    Frame::join(std::slice::from_ref(frame)).unwrap()
}

fn token(seed: u8) -> [u8; 16] {
    [seed; 16]
}

#[test]
fn initial() {
    let rtt = Rtt::new();
    assert_eq!(pto(&rtt), 999_000);
    let idle = Idle::new(0, 1_000, 1_000);
    assert_eq!(idle.span(), Some(1_000_000));
    assert_eq!(idle.deadline(pto(&rtt)), Some(2_997_000));
}

#[test]
fn measured() {
    let mut rtt = Rtt::new();
    rtt.update(0, 100_000, 0);
    assert_eq!(pto(&rtt), 300_000);
    let short = Idle::new(0, 500, 500);
    assert_eq!(short.deadline(pto(&rtt)), Some(900_000));
    let long = Idle::new(0, 2_000, 2_000);
    assert_eq!(long.deadline(pto(&rtt)), Some(2_000_000));
}

#[test]
fn exchange() {
    let step = pto(&Rtt::new());
    let mut near = Life::default();
    let mut far = Life::default();
    near.close(0, step, shut()).unwrap();
    let bytes = wire(near.frame().unwrap());
    let frames = Frame::all(&bytes).unwrap();
    assert_eq!(frames, vec![shut()]);
    far.peer(10, step);
    assert_eq!(far.mode(), Mode::Draining);
    assert_eq!(far.receive(), None);
    let mut sent = Vec::new();
    for count in 1..=5 {
        if let Some(frame) = near.receive() {
            sent.push((count, wire(frame)));
        }
    }
    assert_eq!(
        sent,
        vec![(1, bytes.clone()), (2, bytes.clone()), (4, bytes)]
    );
    assert_eq!(near.deadline(), Some(3 * step));
    assert_eq!(far.deadline(), Some(10 + 3 * step));
    assert!(near.expire(3 * step));
    assert!(!far.expire(3 * step));
    assert!(far.expire(10 + 3 * step));
    assert_eq!((near.mode(), far.mode()), (Mode::Closed, Mode::Closed));
}

#[test]
fn crossed() {
    let step = 1_000;
    let mut left = Life::default();
    let mut right = Life::default();
    left.close(0, step, shut()).unwrap();
    right.close(40, step, shut()).unwrap();
    left.peer(60, step);
    right.peer(50, step);
    assert_eq!(left.mode(), Mode::Draining);
    assert_eq!(right.mode(), Mode::Draining);
    assert_eq!(left.deadline(), Some(3_000));
    assert_eq!(right.deadline(), Some(3_040));
}

#[test]
fn unused() {
    let first = token(1);
    let second = token(2);
    let mut peers = Peers::new(vec![1; 8], Some(first), 8);
    peers.receive(1, 0, &[2; 8], second).unwrap();
    assert!(peers.matches(&first));
    assert!(peers.matches(&second));
    let mut data = vec![0u8; 30];
    data[14..].copy_from_slice(&second);
    assert!(!stateless(&data, &[first]));
    assert!(stateless(&data, &[first, second]));
}

#[test]
fn reaction() {
    let first = token(1);
    let mut data = vec![7u8; 50];
    data[34..].copy_from_slice(&first);
    let mut life = Life::default();
    assert!(stateless(&data, &[first]));
    life.reset(500, 1_000);
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.receive(), None);
    assert!(life.expire(3_500));
}

#[test]
fn refusal() {
    let mut datagram = vec![0u8; 1_200];
    datagram[0] = 0xc3;
    datagram[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
    datagram[5] = 4;
    datagram[6..10].copy_from_slice(&[1, 2, 3, 4]);
    datagram[10] = 2;
    datagram[11..13].copy_from_slice(&[9, 8]);
    let reply = answer(&datagram, &[1], 0x1a2a_3a4a).unwrap().unwrap();
    let bytes = reply.write().unwrap();
    let Ok(Header::Negotiation(parsed)) = Header::parse(&bytes, 2) else {
        panic!("not a negotiation packet");
    };
    assert_eq!(parsed, reply);
    let mut client = Client::new(0x6b33_43cf, &[1, 2, 3, 4], &[9, 8]);
    assert_eq!(client.receive(&parsed), Verdict::Abandon);
    assert_eq!(client.receive(&parsed), Verdict::Ignore);
}

#[test]
fn forged() {
    let mut client = Client::new(1, &[1, 2, 3, 4], &[9, 8]);
    let forged = Negotiation {
        unused: 0,
        dcid: vec![9, 8],
        scid: vec![5, 5, 5, 5],
        versions: vec![2],
    };
    assert_eq!(client.receive(&forged), Verdict::Ignore);
    let valid = Negotiation {
        scid: vec![1, 2, 3, 4],
        ..forged
    };
    assert_eq!(client.receive(&valid), Verdict::Abandon);
}
