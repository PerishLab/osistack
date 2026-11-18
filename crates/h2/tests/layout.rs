use h2::{Codec, Decoder, Dependency, Frame, Header, PREFACE};

fn check(bytes: &[u8], frame: Frame) {
    let codec = Codec::default();
    assert_eq!(codec.decode(bytes), Ok(Some((frame.clone(), bytes.len()))));
    assert_eq!(codec.encode(&frame), Ok(bytes.to_vec()));
}

#[test]
fn preface() {
    assert_eq!(PREFACE.len(), 24);
    assert_eq!(&PREFACE[..], &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
    assert_eq!(
        &PREFACE[..16],
        &[
            0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30,
            0x0d, 0x0a
        ]
    );
}

#[test]
fn data() {
    check(
        &[0, 0, 5, 0, 1, 0, 0, 0, 1, b'h', b'e', b'l', b'l', b'o'],
        Frame::Data {
            stream: 1,
            fin: true,
            pad: None,
            data: b"hello".to_vec(),
        },
    );
    check(
        &[0, 0, 0, 0, 0, 0, 0, 0, 3],
        Frame::Data {
            stream: 3,
            fin: false,
            pad: None,
            data: Vec::new(),
        },
    );
}

#[test]
fn padded() {
    check(
        &[
            0, 0, 9, 0, 8, 0, 0, 0, 1, 3, b'h', b'e', b'l', b'l', b'o', 0, 0, 0,
        ],
        Frame::Data {
            stream: 1,
            fin: false,
            pad: Some(3),
            data: b"hello".to_vec(),
        },
    );
    check(
        &[0, 0, 1, 0, 9, 0, 0, 0, 5, 0],
        Frame::Data {
            stream: 5,
            fin: true,
            pad: Some(0),
            data: Vec::new(),
        },
    );
}

#[test]
fn headers() {
    let bytes = [0, 0, 3, 1, 5, 0, 0, 0, 1, 0x82, 0x86, 0x84];
    let frame = Frame::Headers {
        stream: 1,
        fin: true,
        complete: true,
        pad: None,
        priority: None,
        block: vec![0x82, 0x86, 0x84],
    };
    check(&bytes, frame.clone());
    let Frame::Headers { block, .. } = frame else {
        unreachable!()
    };
    let fields = Decoder::new(4096).decode(&block).unwrap();
    assert_eq!(fields[0], Header::new(b":method", b"GET"));
    assert_eq!(fields[2], Header::new(b":path", b"/"));
}

#[test]
fn urgent() {
    check(
        &[
            0, 0, 9, 1, 0x2c, 0, 0, 0, 5, 2, 0, 0, 0, 3, 0x10, 0x82, 0, 0,
        ],
        Frame::Headers {
            stream: 5,
            fin: false,
            complete: true,
            pad: Some(2),
            priority: Some(Dependency {
                exclusive: false,
                stream: 3,
                weight: 0x10,
            }),
            block: vec![0x82],
        },
    );
    check(
        &[0, 0, 6, 1, 0x20, 0, 0, 0, 7, 0x80, 0, 0, 1, 0xff, 0x84],
        Frame::Headers {
            stream: 7,
            fin: false,
            complete: false,
            pad: None,
            priority: Some(Dependency {
                exclusive: true,
                stream: 1,
                weight: 0xff,
            }),
            block: vec![0x84],
        },
    );
}

#[test]
fn priority() {
    check(
        &[0, 0, 5, 2, 0, 0, 0, 0, 5, 0x80, 0, 0, 3, 0x0f],
        Frame::Priority {
            stream: 5,
            dependency: Dependency {
                exclusive: true,
                stream: 3,
                weight: 15,
            },
        },
    );
}
