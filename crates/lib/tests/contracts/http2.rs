use crate::behaviour::Check;
use h2::{Connection, Decoder, Encoder, Frame, Header, Settings};

pub fn table() -> Vec<(&'static str, Check)> {
    vec![("hpack", hpack as Check)]
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
    let (mut client, _) = Connection::start(Settings::default());
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
