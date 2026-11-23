use crate::behaviour::Check;
use h2::{
    Close, Code, Codec, Connection, Decoder, Encoder, Error, Fault, Frame, Header, Misuse, PREFACE,
    Setting, Settings, State,
};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![
        ("hpack", hpack as Check),
        ("settings", settings as Check),
        ("headers", headers as Check),
        ("continuation", continuation as Check),
        ("data", data as Check),
        ("flow-control", window as Check),
        ("reset-stream", reset as Check),
        ("goaway", goaway as Check),
        ("ping", ping as Check),
        ("concurrent-streams", limited as Check),
        ("connection-reuse", reused as Check),
        ("push-disabled", disabled as Check),
    ]
}

fn trip(frame: &Frame) {
    let codec = Codec::default();
    let bytes = codec.encode(frame).unwrap();
    assert_eq!(codec.decode(&bytes), Ok(Some((frame.clone(), bytes.len()))));
}

fn wire(kind: u8, flags: u8, stream: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut out = length.to_be_bytes()[1..].to_vec();
    out.extend([kind, flags, 0, 0, 0, stream]);
    out.extend(payload);
    out
}

fn refuses(kind: u8, flags: u8, stream: u8, payload: &[u8]) -> Error {
    Codec::default()
        .decode(&wire(kind, flags, stream, payload))
        .unwrap_err()
}

fn settings() {
    trip(&Frame::Settings {
        ack: false,
        list: vec![Setting { id: 3, value: 100 }, Setting { id: 2, value: 0 }],
    });
    trip(&Frame::Settings {
        ack: true,
        list: Vec::new(),
    });
    assert_eq!(refuses(4, 1, 0, &[0; 6]), Error::Length);
    assert_eq!(refuses(4, 0, 1, &[]), Error::Stream);
}

fn headers() {
    trip(&Frame::Headers {
        stream: 1,
        fin: true,
        complete: true,
        pad: None,
        priority: None,
        block: vec![0x82, 0x86, 0x84],
    });
    assert_eq!(refuses(1, 4, 0, &[0x82]), Error::Stream);
}

fn continuation() {
    trip(&Frame::Continuation {
        stream: 1,
        complete: true,
        block: vec![0x84, 0x86],
    });
    assert_eq!(refuses(9, 4, 0, &[0x84]), Error::Stream);
}

fn data() {
    trip(&Frame::Data {
        stream: 1,
        fin: true,
        pad: None,
        data: b"hello".to_vec(),
    });
    assert_eq!(refuses(0, 0, 0, &[1]), Error::Stream);
    assert_eq!(refuses(0, 8, 1, &[4, 1, 2, 3]), Error::Padding);
}

fn window() {
    trip(&Frame::Window {
        stream: 1,
        increment: 65536,
    });
    assert_eq!(refuses(8, 0, 1, &[0, 0, 0, 0]), Error::Increment);
}

fn reset() {
    trip(&Frame::Reset { stream: 3, code: 8 });
    assert_eq!(refuses(3, 0, 0, &[0; 4]), Error::Stream);
}

fn goaway() {
    trip(&Frame::Goaway {
        last: 5,
        code: 2,
        debug: b"hi".to_vec(),
    });
    assert_eq!(refuses(7, 0, 1, &[0; 8]), Error::Stream);
}

fn ping() {
    trip(&Frame::Ping {
        ack: false,
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    });
    trip(&Frame::Ping {
        ack: true,
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    });
    assert_eq!(refuses(6, 0, 1, &[0; 8]), Error::Stream);
}

fn request() -> Vec<Header> {
    vec![
        Header::new(b":method", b"GET"),
        Header::new(b":path", b"/index"),
        Header::new(b":scheme", b"http"),
        Header::new(b":authority", b"example.test"),
        Header::secret(b"authorization", b"token"),
    ]
}

fn answer() -> Vec<Header> {
    vec![
        Header::new(b":status", b"200"),
        Header::new(b"content-type", b"text/plain"),
    ]
}

fn first(frames: Vec<Frame>) -> Vec<u8> {
    match frames.into_iter().next() {
        Some(Frame::Headers { block, .. }) => block,
        other => panic!("{other:?}"),
    }
}

fn ready() -> Connection {
    let (mut client, _) = Connection::start(Settings::default()).unwrap();
    for ack in [false, true] {
        let frame = Frame::Settings {
            ack,
            list: Vec::new(),
        };
        client.receive(&frame).unwrap();
    }
    client
}

fn hpack() {
    let mut client = ready();
    let mut peer = Decoder::new(4096);
    let mut sizes = Vec::new();
    for stream in [1, 3, 5] {
        let block = first(client.headers(stream, &request(), false).unwrap());
        assert_eq!(peer.decode(&block).unwrap(), request());
        sizes.push(block.len());
    }
    assert!(sizes[1] < sizes[0]);
    assert_eq!(sizes[2], sizes[1]);
    assert!(!client.encoder().dynamic().is_empty());
    assert_eq!(client.encoder().dynamic(), peer.dynamic());
    assert!(
        peer.dynamic()
            .iter()
            .all(|entry| entry.name != b"authorization")
    );
    let mut source = Encoder::new(4096, true);
    for fin in [false, true] {
        let frame = Frame::Headers {
            stream: 1,
            fin,
            complete: true,
            pad: None,
            priority: None,
            block: source.encode(&answer()),
        };
        let block = client.receive(&frame).unwrap().block.unwrap();
        assert_eq!((block.stream, block.fin, block.fields), (1, fin, answer()));
    }
    assert_eq!(client.decoder().dynamic(), source.dynamic());
}

fn limited() {
    let (mut client, _) = Connection::start(Settings::default()).unwrap();
    client
        .receive(&Frame::Settings {
            ack: false,
            list: vec![Setting { id: 3, value: 1 }],
        })
        .unwrap();
    client
        .receive(&Frame::Settings {
            ack: true,
            list: Vec::new(),
        })
        .unwrap();
    client.headers(1, &request(), true).unwrap();
    assert_eq!(client.headers(3, &request(), true), Err(Misuse::Limit));
}

fn reused() {
    let mut client = ready();
    client.headers(1, &request(), true).unwrap();
    let block = Encoder::new(4096, true).encode(&answer());
    client
        .receive(&Frame::Headers {
            stream: 1,
            fin: true,
            complete: true,
            pad: None,
            priority: None,
            block,
        })
        .unwrap();
    assert_eq!(client.streams().state(1), State::Closed(Close::Finished));
    client.headers(3, &request(), true).unwrap();
    assert_eq!(client.streams().active(), 1);
}

fn disabled() {
    let (mut client, bytes) = Connection::start(Settings::default()).unwrap();
    let (frame, _) = Codec::default()
        .decode(&bytes[PREFACE.len()..])
        .unwrap()
        .unwrap();
    match frame {
        Frame::Settings { ack: false, list } => {
            assert!(list.contains(&Setting { id: 2, value: 0 }));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        client.receive(&Frame::Settings {
            ack: false,
            list: vec![Setting { id: 2, value: 1 }],
        }),
        Err(Fault::Connection {
            code: Code::Protocol,
        })
    );
}
