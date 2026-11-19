use h2::{Codec, Dependency, Error, Frame, Setting};

fn decode(bytes: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
    Codec::default().decode(bytes)
}

fn frame(kind: u8, flags: u8, stream: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut bytes = length.to_be_bytes()[1..].to_vec();
    bytes.extend([kind, flags, 0, 0, 0, stream]);
    bytes.extend(payload);
    bytes
}

#[test]
fn oversize() {
    assert_eq!(decode(&[0, 0x40, 1, 0, 0, 0, 0, 0, 1]), Err(Error::Length));
    assert_eq!(decode(&[0, 0x40, 0, 0, 0, 0, 0, 0, 1]), Ok(None));
    let wide = Codec::new(0xff_ffff).unwrap();
    assert_eq!(wide.decode(&[0, 0x40, 1, 0, 0, 0, 0, 0, 1]), Ok(None));
    assert_eq!(wide.decode(&[0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 1]), Ok(None));
    assert_eq!(Codec::new(16384).unwrap(), Codec::default());
}

#[test]
fn limits() {
    assert_eq!(Codec::new(16383), Err(Error::Setting));
    assert_eq!(Codec::new(0x100_0000), Err(Error::Setting));
    assert_eq!(Codec::new(0), Err(Error::Setting));
}

#[test]
fn fixed() {
    assert_eq!(decode(&frame(2, 0, 1, &[0; 4])), Err(Error::Length));
    assert_eq!(decode(&frame(2, 0, 1, &[0; 6])), Err(Error::Length));
    assert_eq!(decode(&frame(3, 0, 1, &[0; 3])), Err(Error::Length));
    assert_eq!(decode(&frame(3, 0, 1, &[0; 5])), Err(Error::Length));
    assert_eq!(decode(&frame(6, 0, 0, &[0; 7])), Err(Error::Length));
    assert_eq!(decode(&frame(6, 0, 0, &[0; 9])), Err(Error::Length));
    assert_eq!(decode(&frame(8, 0, 1, &[0, 0, 0])), Err(Error::Length));
    assert_eq!(
        decode(&frame(8, 0, 1, &[0, 0, 0, 1, 0])),
        Err(Error::Length)
    );
    assert_eq!(decode(&frame(7, 0, 0, &[0; 7])), Err(Error::Length));
}

#[test]
fn settings() {
    assert_eq!(decode(&frame(4, 0, 0, &[0; 5])), Err(Error::Length));
    assert_eq!(decode(&frame(4, 0, 0, &[0; 7])), Err(Error::Length));
    assert_eq!(decode(&frame(4, 1, 0, &[0; 6])), Err(Error::Length));
    assert_eq!(
        decode(&frame(4, 0, 0, &[0, 2, 0, 0, 0, 2])),
        Err(Error::Setting)
    );
    assert_eq!(
        decode(&frame(4, 0, 0, &[0, 4, 0x80, 0, 0, 0])),
        Err(Error::Setting)
    );
    assert_eq!(
        decode(&frame(4, 0, 0, &[0, 5, 0, 0, 0x3f, 0xff])),
        Err(Error::Setting)
    );
    assert_eq!(
        decode(&frame(4, 0, 0, &[0, 5, 1, 0, 0, 0])),
        Err(Error::Setting)
    );
    assert!(
        decode(&frame(4, 0, 0, &[0, 5, 0, 0, 0x40, 0]))
            .unwrap()
            .is_some()
    );
    assert!(
        decode(&frame(4, 0, 0, &[0, 5, 0, 0xff, 0xff, 0xff]))
            .unwrap()
            .is_some()
    );
    assert!(
        decode(&frame(4, 0, 0, &[0, 4, 0x7f, 0xff, 0xff, 0xff]))
            .unwrap()
            .is_some()
    );
}

#[test]
fn streams() {
    assert_eq!(decode(&frame(0, 0, 0, &[1])), Err(Error::Stream));
    assert_eq!(decode(&frame(1, 4, 0, &[0x82])), Err(Error::Stream));
    assert_eq!(decode(&frame(2, 0, 0, &[0; 5])), Err(Error::Stream));
    assert_eq!(decode(&frame(3, 0, 0, &[0; 4])), Err(Error::Stream));
    assert_eq!(decode(&frame(9, 4, 0, &[0x84])), Err(Error::Stream));
    assert_eq!(decode(&frame(4, 0, 1, &[])), Err(Error::Stream));
    assert_eq!(decode(&frame(6, 0, 1, &[0; 8])), Err(Error::Stream));
    assert_eq!(decode(&frame(7, 0, 1, &[0; 8])), Err(Error::Stream));
}

#[test]
fn padding() {
    assert_eq!(decode(&frame(0, 8, 1, &[])), Err(Error::Length));
    assert_eq!(decode(&frame(0, 8, 1, &[1])), Err(Error::Padding));
    assert_eq!(decode(&frame(0, 8, 1, &[4, 1, 2, 3])), Err(Error::Padding));
    assert_eq!(decode(&frame(0, 8, 1, &[200, 1])), Err(Error::Padding));
    assert!(decode(&frame(0, 8, 1, &[3, 1, 2, 3])).unwrap().is_some());
    assert!(decode(&frame(0, 8, 1, &[0])).unwrap().is_some());
    assert_eq!(decode(&frame(1, 8, 1, &[2, 0x82])), Err(Error::Padding));
    assert_eq!(decode(&frame(1, 8, 1, &[])), Err(Error::Length));
}

#[test]
fn urgent() {
    assert_eq!(
        decode(&frame(1, 0x20, 1, &[0, 0, 0, 1])),
        Err(Error::Length)
    );
    assert_eq!(decode(&frame(1, 0x20, 1, &[])), Err(Error::Length));
    assert_eq!(
        decode(&frame(1, 0x28, 1, &[1, 0, 0, 0, 0])),
        Err(Error::Length)
    );
    assert!(
        decode(&frame(1, 0x20, 1, &[0, 0, 0, 1, 7]))
            .unwrap()
            .is_some()
    );
}

#[test]
fn increment() {
    assert_eq!(
        decode(&frame(8, 0, 1, &[0, 0, 0, 0])),
        Err(Error::Increment)
    );
    assert_eq!(
        decode(&frame(8, 0, 0, &[0, 0, 0, 0])),
        Err(Error::Increment)
    );
    assert_eq!(
        decode(&frame(8, 0, 1, &[0x80, 0, 0, 0])),
        Err(Error::Increment)
    );
}

#[test]
fn push() {
    assert_eq!(
        decode(&frame(5, 4, 1, &[0, 0, 0, 2, 0x82])),
        Err(Error::Push)
    );
}

#[test]
fn encoding() {
    let codec = Codec::default();
    let big = Frame::Data {
        stream: 1,
        fin: false,
        pad: None,
        data: vec![0; 16385],
    };
    assert_eq!(codec.encode(&big), Err(Error::Length));
    let fits = Frame::Data {
        stream: 1,
        fin: false,
        pad: None,
        data: vec![0; 16384],
    };
    assert_eq!(codec.encode(&fits).unwrap().len(), 16393);
    let padded = Frame::Data {
        stream: 1,
        fin: false,
        pad: Some(1),
        data: vec![0; 16384],
    };
    assert_eq!(codec.encode(&padded), Err(Error::Length));
    let zero = Frame::Data {
        stream: 0,
        fin: false,
        pad: None,
        data: Vec::new(),
    };
    assert_eq!(codec.encode(&zero), Err(Error::Stream));
    let wide = Frame::Reset {
        stream: 0x8000_0000,
        code: 1,
    };
    assert_eq!(codec.encode(&wide), Err(Error::Stream));
    let ping = Frame::Settings {
        ack: false,
        list: Vec::new(),
    };
    assert!(codec.encode(&ping).is_ok());
}

#[test]
fn building() {
    let codec = Codec::default();
    let window = |increment| Frame::Window {
        stream: 1,
        increment,
    };
    assert_eq!(codec.encode(&window(0)), Err(Error::Increment));
    assert_eq!(codec.encode(&window(0x8000_0000)), Err(Error::Increment));
    assert!(codec.encode(&window(0x7fff_ffff)).is_ok());
    let acked = Frame::Settings {
        ack: true,
        list: vec![Setting { id: 3, value: 1 }],
    };
    assert_eq!(codec.encode(&acked), Err(Error::Length));
    let bad = Frame::Settings {
        ack: false,
        list: vec![Setting { id: 2, value: 2 }],
    };
    assert_eq!(codec.encode(&bad), Err(Error::Setting));
    let known = Frame::Unknown {
        kind: 0,
        flags: 0,
        stream: 1,
        payload: Vec::new(),
    };
    assert_eq!(codec.encode(&known), Err(Error::Kind));
    let push = Frame::Unknown {
        kind: 5,
        flags: 0,
        stream: 1,
        payload: Vec::new(),
    };
    assert_eq!(codec.encode(&push), Err(Error::Kind));
    let goaway = Frame::Goaway {
        last: 0x8000_0000,
        code: 0,
        debug: Vec::new(),
    };
    assert_eq!(codec.encode(&goaway), Err(Error::Stream));
    let priority = Frame::Priority {
        stream: 1,
        dependency: Dependency {
            exclusive: false,
            stream: 0x8000_0000,
            weight: 0,
        },
    };
    assert_eq!(codec.encode(&priority), Err(Error::Stream));
}
