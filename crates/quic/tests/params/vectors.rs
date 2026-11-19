use crate::data::*;
use crate::support::*;
use quic::{Direction, Param, Params, Side};

#[test]
fn client() {
    let frame = hex(INITIAL);
    let tail = &frame[frame.len() - 54..];
    assert_eq!(tail[..4], hex("0039 0032"));
    let bytes = &tail[4..];
    assert_eq!(bytes.len(), 50);
    let expected = vec![
        Param::Data((1 << 62) - 1),
        Param::Window(Side::Local, 65535),
        Param::Window(Side::Uni, 65535),
        Param::Streams(Direction::Bidi, 16),
        Param::Idle(30000),
        Param::Streams(Direction::Uni, 16),
        Param::Source(hex("8394c8f03e515708")),
        Param::Window(Side::Remote, 65535),
    ];
    let found = Params::parse(bytes).unwrap();
    assert_eq!(found.list, expected);
    assert_eq!(found.write().unwrap(), bytes);
}
