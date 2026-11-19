use crate::behaviour::Check;
use crate::quic::wire;
use quic::{Allowance, Credit, Direction, Fault, Frame, Inbound, Lanes, Role, Stream};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("stream-flow-control", single as Check),
        ("connection-flow-control", shared as Check),
    ]
}

fn carried(id: u64, offset: u64, size: u64, fin: bool) -> Stream {
    let data = vec![7; size as usize];
    let frame = Frame::Stream(Stream {
        id,
        offset,
        data,
        fin,
        sized: true,
    });
    let Frame::Stream(found) = wire(&[frame]).remove(0) else {
        panic!("not a stream frame");
    };
    found
}

fn deliver(inbound: &mut Inbound, stream: &Stream) -> Result<u64, Fault> {
    inbound.data(stream.offset, stream.data.len() as u64, stream.fin)
}

fn single() {
    let mut out = Credit::new(100);
    let mut inbound = Inbound::new(100);
    let first = carried(0, 0, out.take(60), false);
    assert_eq!(deliver(&mut inbound, &first), Ok(60));
    let want = out.take(60);
    assert_eq!(want, 40);
    let second = carried(0, 60, want, false);
    assert_eq!(deliver(&mut inbound, &second), Ok(40));
    assert_eq!(out.take(1), 0);
    let limit = out.stalled().unwrap();
    let frame = Frame::Stalled { stream: 0, limit };
    assert_eq!(
        wire(&[frame]),
        vec![Frame::Stalled {
            stream: 0,
            limit: 100
        }]
    );
    assert_eq!(out.stalled(), None);
    inbound.consume(49);
    assert_eq!(inbound.grant(), None);
    inbound.consume(1);
    let limit = inbound.grant().unwrap();
    assert_eq!(limit, 150);
    let Frame::Window { stream, limit } = wire(&[Frame::Window { stream: 0, limit }])[0] else {
        panic!("not a window frame");
    };
    assert_eq!(stream, 0);
    assert!(out.raise(limit));
    assert!(!out.raise(limit));
    assert!(!out.raise(120));
    assert_eq!(out.room(), 50);
    let third = carried(0, 100, out.take(60), false);
    assert_eq!(deliver(&mut inbound, &third), Ok(50));
    assert_eq!(out.stalled(), Some(150));
    let late = carried(0, 150, 1, false);
    assert_eq!(deliver(&mut inbound, &late), Err(Fault::Flow));
    assert_eq!(deliver(&mut inbound, &first), Ok(0));
    assert_eq!(inbound.grant(), None);
    inbound.consume(1000);
    assert_eq!(inbound.grant(), Some(250));
    ends();
    lanes();
}

fn ends() {
    let mut whole = Inbound::new(100);
    assert_eq!(deliver(&mut whole, &carried(4, 0, 50, true)), Ok(50));
    let past = carried(4, 50, 10, false);
    assert_eq!(deliver(&mut whole, &past), Err(Fault::Final));
    let mut open = Inbound::new(100);
    assert_eq!(deliver(&mut open, &carried(4, 0, 60, false)), Ok(60));
    let short = carried(4, 0, 50, true);
    assert_eq!(deliver(&mut open, &short), Err(Fault::Final));
    assert_eq!(open.reset(40), Err(Fault::Final));
    assert_eq!(open.reset(60), Ok(0));
    assert_eq!(open.last(), Some(60));
}

fn lanes() {
    let mut client = Lanes::new(Role::Client, [2, 1], [0, 0]);
    let mut server = Lanes::new(Role::Server, [0, 0], [2, 1]);
    assert_eq!(client.open(Direction::Bidi), Ok(0));
    assert_eq!(client.open(Direction::Bidi), Ok(4));
    let choked = client.open(Direction::Bidi).unwrap_err();
    let frame = Frame::Choked {
        kind: Direction::Bidi,
        limit: choked.0,
    };
    assert_eq!(
        wire(&[frame]),
        vec![Frame::Choked {
            kind: Direction::Bidi,
            limit: 2
        }]
    );
    assert_eq!(client.stalled(Direction::Bidi), Some(2));
    assert_eq!(client.stalled(Direction::Bidi), None);
    assert_eq!(client.admit(0), Ok(vec![]));
    assert_eq!(server.admit(1), Err(Fault::State));
    assert_eq!(server.admit(0), Ok(vec![0]));
    assert_eq!(server.admit(4), Ok(vec![4]));
    assert_eq!(server.admit(8), Err(Fault::Limit));
    assert_eq!(server.grant(Direction::Bidi), None);
    server.close(0);
    server.close(4);
    let limit = server.grant(Direction::Bidi).unwrap();
    let frame = Frame::Streams {
        kind: Direction::Bidi,
        limit,
    };
    let Frame::Streams { kind, limit } = wire(&[frame]).remove(0) else {
        panic!("not a streams frame");
    };
    assert_eq!((kind, limit), (Direction::Bidi, 4));
    assert!(client.raise(kind, limit));
    assert!(!client.raise(kind, limit));
    assert_eq!(client.open(Direction::Bidi), Ok(8));
    assert_eq!(server.admit(16), Err(Fault::Limit));
    assert_eq!(server.admit(12), Ok(vec![8, 12]));
    assert_eq!(client.open(Direction::Uni), Ok(2));
    assert!(client.open(Direction::Uni).is_err());
    assert_eq!(client.admit(2), Err(Fault::State));
    assert_eq!(server.admit(2), Ok(vec![2]));
    assert_eq!(server.admit(6), Err(Fault::Limit));
}

fn shared() {
    let mut total = Credit::new(150);
    let mut left = Credit::new(100);
    let mut right = Credit::new(100);
    let mut inbound = [Inbound::new(100), Inbound::new(100)];
    let mut limit = Allowance::new(150, Fault::Flow);
    let sizes = [left.share(&mut total, 100), right.share(&mut total, 100)];
    assert_eq!(sizes, [100, 50]);
    assert_eq!((total.used(), total.room()), (150, 0));
    for (at, size) in sizes.into_iter().enumerate() {
        let stream = carried(at as u64 * 4, 0, size, false);
        let fresh = deliver(&mut inbound[at], &stream).unwrap();
        assert_eq!(limit.charge(fresh), Ok(fresh));
    }
    assert_eq!(left.share(&mut total, 1), 0);
    let blocked = total.stalled().unwrap();
    assert_eq!(wire(&[Frame::Blocked(blocked)]), vec![Frame::Blocked(150)]);
    assert_eq!(total.stalled(), None);
    assert_eq!(right.stalled(), None);
    let again = carried(0, 0, 100, false);
    assert_eq!(deliver(&mut inbound[0], &again), Ok(0));
    assert_eq!(limit.highest(), 150);
    assert_eq!(limit.charge(1), Err(Fault::Flow));
    limit.consume(50);
    assert_eq!(limit.grant(), None);
    limit.consume(1000);
    let grown = limit.grant().unwrap();
    let Frame::Data(raised) = wire(&[Frame::Data(grown)]).remove(0) else {
        panic!("not a data frame");
    };
    assert_eq!(raised, 300);
    assert!(total.raise(raised));
    assert!(!total.raise(raised));
    assert_eq!(right.share(&mut total, 100), 50);
    assert_eq!(left.share(&mut total, 100), 0);
    assert_eq!(total.used(), 200);
    assert_eq!(limit.grant(), None);
}
