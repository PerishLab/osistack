use h2::{Codec, Frame, Setting};

fn check(bytes: &[u8], frame: Frame) {
    let codec = Codec::default();
    assert_eq!(codec.decode(bytes), Ok(Some((frame.clone(), bytes.len()))));
    assert_eq!(codec.encode(&frame), Ok(bytes.to_vec()));
}

#[test]
fn reset() {
    check(
        &[0, 0, 4, 3, 0, 0, 0, 0, 3, 0, 0, 0, 8],
        Frame::Reset { stream: 3, code: 8 },
    );
}

#[test]
fn settings() {
    check(
        &[0, 0, 0, 4, 0, 0, 0, 0, 0],
        Frame::Settings {
            ack: false,
            list: Vec::new(),
        },
    );
    check(
        &[0, 0, 0, 4, 1, 0, 0, 0, 0],
        Frame::Settings {
            ack: true,
            list: Vec::new(),
        },
    );
    check(
        &[
            0, 0, 18, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 4, 0, 0, 0xff, 0xff, 0, 2, 0, 0, 0,
            0,
        ],
        Frame::Settings {
            ack: false,
            list: vec![
                Setting { id: 3, value: 100 },
                Setting {
                    id: 4,
                    value: 65535,
                },
                Setting { id: 2, value: 0 },
            ],
        },
    );
    check(
        &[
            0, 0, 6, 4, 0, 0, 0, 0, 0, 0xff, 0xee, 0xde, 0xad, 0xbe, 0xef,
        ],
        Frame::Settings {
            ack: false,
            list: vec![Setting {
                id: 0xffee,
                value: 0xdeadbeef,
            }],
        },
    );
}

#[test]
fn ping() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    check(
        &[0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
        Frame::Ping { ack: false, data },
    );
    check(
        &[0, 0, 8, 6, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
        Frame::Ping { ack: true, data },
    );
}

#[test]
fn goaway() {
    check(
        &[
            0, 0, 10, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 2, b'h', b'i',
        ],
        Frame::Goaway {
            last: 5,
            code: 2,
            debug: b"hi".to_vec(),
        },
    );
    check(
        &[
            0, 0, 8, 7, 0, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0,
        ],
        Frame::Goaway {
            last: 0x7fff_ffff,
            code: 0,
            debug: Vec::new(),
        },
    );
}

#[test]
fn window() {
    check(
        &[0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 1, 0, 0],
        Frame::Window {
            stream: 1,
            increment: 65536,
        },
    );
    check(
        &[0, 0, 4, 8, 0, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff],
        Frame::Window {
            stream: 0,
            increment: 0x7fff_ffff,
        },
    );
}

#[test]
fn continuation() {
    check(
        &[0, 0, 2, 9, 4, 0, 0, 0, 1, 0x84, 0x86],
        Frame::Continuation {
            stream: 1,
            complete: true,
            block: vec![0x84, 0x86],
        },
    );
    check(
        &[0, 0, 0, 9, 0, 0, 0, 0, 1],
        Frame::Continuation {
            stream: 1,
            complete: false,
            block: Vec::new(),
        },
    );
}

#[test]
fn unknown() {
    check(
        &[0, 0, 3, 0xfa, 0x12, 0, 0, 0, 7, 1, 2, 3],
        Frame::Unknown {
            kind: 0xfa,
            flags: 0x12,
            stream: 7,
            payload: vec![1, 2, 3],
        },
    );
    check(
        &[0, 0, 0, 10, 0, 0, 0, 0, 0],
        Frame::Unknown {
            kind: 10,
            flags: 0,
            stream: 0,
            payload: Vec::new(),
        },
    );
}

#[test]
fn ignored() {
    let codec = Codec::default();
    let reserved = [0, 0, 1, 0, 0, 0x80, 0, 0, 1, 7];
    let frame = Frame::Data {
        stream: 1,
        fin: false,
        pad: None,
        data: vec![7],
    };
    assert_eq!(codec.decode(&reserved), Ok(Some((frame, 10))));
    let flags = [0, 0, 1, 0, 0x06, 0, 0, 0, 1, 7];
    let Ok(Some((Frame::Data { fin, pad, .. }, _))) = codec.decode(&flags) else {
        panic!("data expected")
    };
    assert_eq!((fin, pad), (false, None));
    let window = [0, 0, 4, 8, 0, 0, 0, 0, 1, 0x80, 0, 0, 5];
    let frame = Frame::Window {
        stream: 1,
        increment: 5,
    };
    assert_eq!(codec.decode(&window), Ok(Some((frame, 13))));
    let last = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0x80, 0, 0, 9, 0, 0, 0, 1];
    let frame = Frame::Goaway {
        last: 9,
        code: 1,
        debug: Vec::new(),
    };
    assert_eq!(codec.decode(&last), Ok(Some((frame, 17))));
}

#[test]
fn trailing() {
    let bytes = [0, 0, 1, 0, 0, 0, 0, 0, 1, 7, 0xde, 0xad];
    let Ok(Some((_, used))) = Codec::default().decode(&bytes) else {
        panic!("frame expected")
    };
    assert_eq!(used, 10);
}
