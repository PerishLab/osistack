use crate::support::*;
use h3::{Code, Frame, Framer};

const LIMIT: usize = 1 << 20;
const GIB: u64 = 1 << 30;

fn chunks(framer: &mut Framer, total: u64) -> u64 {
    let zeros = vec![0u8; 1 << 22];
    let mut left = total;
    let mut seen = 0;
    while left > 0 {
        let take = left.min(zeros.len() as u64) as usize;
        for frame in framer.feed(&zeros[..take]).unwrap() {
            if let Frame::Data(data) = frame {
                seen += data.len() as u64;
            }
        }
        left -= take as u64;
    }
    seen
}

#[test]
fn eightbyte() {
    let wide = bytes("00 c0 00 00 00 00 00 00 02 68 69");
    let (frame, used) = Frame::decode(&wide, LIMIT).unwrap().unwrap();
    assert_eq!(frame, Frame::Data(b"hi".to_vec()));
    assert_eq!(used, wide.len());
    let goaway = bytes("07 c0 00 00 00 00 00 00 01 08");
    let (frame, used) = Frame::decode(&goaway, LIMIT).unwrap().unwrap();
    assert_eq!(frame, Frame::Goaway(8));
    assert_eq!(used, goaway.len());
}

#[test]
fn partial() {
    let whole = bytes("00 c0 00 00 00 00 00 00 02 68 69");
    for cut in 0..whole.len() {
        assert_eq!(Frame::decode(&whole[..cut], LIMIT), Ok(None), "{cut}");
    }
}

#[test]
fn oversized() {
    let heads = [
        "00 bf ff ff ff",
        "00 c0 00 00 00 40 00 00 00",
        "01 c0 00 00 01 00 00 00 00",
        "00 ff ff ff ff ff ff ff ff",
        "00 c0 ff ff ff ff ff ff ff",
    ];
    for head in heads {
        let input = bytes(head);
        let fault = Frame::decode(&input, LIMIT).unwrap_err();
        assert_eq!(fault, connection(Code::Load), "{head}");
        let mut framer = Framer::new(LIMIT);
        assert_eq!(framer.feed(&input), Err(connection(Code::Load)), "{head}");
    }
}

#[test]
fn gibibyte() {
    let mut framer = Framer::new(64);
    let head = bytes("21 c0 00 00 00 40 00 00 00");
    let seen = framer.feed(&head).unwrap();
    assert_eq!(
        seen,
        vec![Frame::Unknown {
            kind: 0x21,
            length: GIB
        }]
    );
    chunks(&mut framer, GIB - 1);
    assert!(!framer.complete());
    assert_eq!(framer.pending(), 0);
    let next = Frame::Data(b"ok".to_vec());
    let mut input = vec![9];
    input.extend(next.encode().unwrap());
    assert_eq!(framer.feed(&input).unwrap(), vec![next]);
    assert!(framer.complete());
}

#[test]
fn streamed() {
    let mut framer = Framer::streaming(64);
    assert!(
        framer
            .feed(&bytes("00 c0 00 00 00 40 00 00 00"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(chunks(&mut framer, GIB), GIB);
    assert!(framer.complete());
    let next = Frame::Headers(vec![1, 2]);
    assert_eq!(framer.feed(&next.encode().unwrap()).unwrap(), vec![next]);
}
