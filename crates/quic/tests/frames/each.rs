use crate::support::*;
use quic::{Direction, Ecn, Frame};

#[test]
fn padding() {
    same("00", Frame::Padding(1));
    same("00000000", Frame::Padding(4));
    let (frame, used) = Frame::parse(&hex("00 00 01")).unwrap();
    assert_eq!((frame, used), (Frame::Padding(2), 2));
    let all = Frame::all(&hex("00 00 01 00 00 00")).unwrap();
    assert_eq!(all, vec![Frame::Padding(2), Frame::Ping, Frame::Padding(3)]);
}

#[test]
fn ping() {
    same("01", Frame::Ping);
}

#[test]
fn ranges() {
    same("02 0a 05 00 02", Frame::Ack(ack(10, 5, 2, &[])));
    same("02 05 412c 00 00", Frame::Ack(ack(5, 300, 0, &[])));
    let many = ack(20, 0, 3, &[(1, 2), (0, 1)]);
    same("02 14 00 02 03 01 02 00 01", Frame::Ack(many));
}

#[test]
fn counts() {
    let ecn = Some(Ecn {
        ect0: 5,
        ect1: 6,
        ce: 7,
    });
    let mut plain = ack(20, 0, 3, &[]);
    plain.ecn = ecn;
    same("03 14 00 00 03 05 06 07", Frame::Ack(plain));
    let mut many = ack(20, 0, 3, &[(1, 2)]);
    many.ecn = ecn;
    same("03 14 00 01 03 01 02 05 06 07", Frame::Ack(many));
}

#[test]
fn stops() {
    let reset = Frame::Reset {
        stream: 1,
        code: 2,
        size: 3,
    };
    same("04 01 02 03", reset);
    same("05 04 07", Frame::Stop { stream: 4, code: 7 });
}

#[test]
fn crypto() {
    let data = b"abc".to_vec();
    same("06 05 03 616263", Frame::Crypto { offset: 5, data });
    same(
        "06 00 00",
        Frame::Crypto {
            offset: 0,
            data: vec![],
        },
    );
}

#[test]
fn fresh() {
    same("07 02 aabb", Frame::Token(vec![0xaa, 0xbb]));
}

#[test]
fn streams() {
    let abc = b"abc";
    same("08 04 616263", stream(4, 0, abc, (false, false)));
    same("09 04 616263", stream(4, 0, abc, (true, false)));
    same("0a 04 03 616263", stream(4, 0, abc, (false, true)));
    same("0b 04 03 616263", stream(4, 0, abc, (true, true)));
    same("0c 04 02 616263", stream(4, 2, abc, (false, false)));
    same("0d 04 02 616263", stream(4, 2, abc, (true, false)));
    same("0e 04 02 03 616263", stream(4, 2, abc, (false, true)));
    same("0f 04 02 03 616263", stream(4, 2, abc, (true, true)));
}

#[test]
fn empty() {
    same("08 04", stream(4, 0, b"", (false, false)));
    same("0a 04 00", stream(4, 0, b"", (false, true)));
    same("0f 04 02 00", stream(4, 2, b"", (true, true)));
}

#[test]
fn offset() {
    let (frame, used) = Frame::parse(&hex("0e 04 00 03 616263")).unwrap();
    assert_eq!(frame, stream(4, 0, b"abc", (false, true)));
    assert_eq!(used, 7);
    assert_eq!(frame.write().unwrap(), hex("0a 04 03 616263"));
}

#[test]
fn open() {
    let all = Frame::all(&hex("08 04 616263")).unwrap();
    assert_eq!(all, vec![stream(4, 0, b"abc", (false, false))]);
    let (frame, used) = Frame::parse(&hex("0a 04 03 616263 01")).unwrap();
    assert_eq!((frame, used), (stream(4, 0, b"abc", (false, true)), 6));
}

#[test]
fn limits() {
    same("10 40ff", Frame::Data(255));
    same(
        "11 04 4400",
        Frame::Window {
            stream: 4,
            limit: 1024,
        },
    );
    same("14 2a", Frame::Blocked(42));
    same(
        "15 04 2a",
        Frame::Stalled {
            stream: 4,
            limit: 42,
        },
    );
}

#[test]
fn directions() {
    let kinds = [(0, Direction::Bidi), (1, Direction::Uni)];
    for (bit, kind) in kinds {
        same(
            &format!("{:02x} 10", 0x12 + bit),
            Frame::Streams { kind, limit: 16 },
        );
        same(
            &format!("{:02x} 10", 0x16 + bit),
            Frame::Choked { kind, limit: 16 },
        );
    }
}

#[test]
fn ceiling() {
    let limit = 1 << 60;
    let kind = Direction::Bidi;
    same("12 d000000000000000", Frame::Streams { kind, limit });
    same("16 d000000000000000", Frame::Choked { kind, limit });
}

#[test]
fn issue() {
    let frame = Frame::Issue {
        sequence: 2,
        retire: 1,
        cid: vec![1, 2, 3, 4],
        token: token(),
    };
    same(&format!("18 02 01 04 01020304 {TOKEN}"), frame);
    for size in [1usize, 20] {
        let cid = vec![7u8; size];
        let text = format!("18 03 03 {size:02x} {} {TOKEN}", "07".repeat(size));
        same(
            &text,
            Frame::Issue {
                sequence: 3,
                retire: 3,
                cid,
                token: token(),
            },
        );
    }
}

#[test]
fn paths() {
    same("19 03", Frame::Retire(3));
    same(
        "1a 0102030405060708",
        Frame::Challenge([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    same(
        "1b 0807060504030201",
        Frame::Response([8, 7, 6, 5, 4, 3, 2, 1]),
    );
}

#[test]
fn closing() {
    let transport = Frame::Transport {
        code: 10,
        frame: 6,
        reason: b"abc".to_vec(),
    };
    same("1c 0a 06 03 616263", transport);
    let bare = Frame::Transport {
        code: 0,
        frame: 0,
        reason: vec![],
    };
    same("1c 00 00 00", bare);
    let application = Frame::Application {
        code: 11,
        reason: b"hi".to_vec(),
    };
    same("1d 0b 02 6869", application);
    same(
        "1d 00 00",
        Frame::Application {
            code: 0,
            reason: vec![],
        },
    );
    same("1e", Frame::Done);
}
