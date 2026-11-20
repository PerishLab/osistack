mod alt;

use crate::behaviour::Check;
use h3::{
    Code, Control, Decoder, Encoder, Error, Event, Fault, Feedback, Field, Frame, Going, Misuse,
    Notice, Request, Sender, Settings, Streams,
};

pub fn table() -> Vec<(&'static str, Check)> {
    let mut rows = vec![
        ("control-stream", control as Check),
        ("settings", values as Check),
        ("headers", headers as Check),
        ("data", body as Check),
        ("goaway", goaway as Check),
        ("qpack", qpack as Check),
        ("blocked-streams", blocked as Check),
    ];
    rows.extend(alt::table());
    rows
}

const LIMIT: usize = 1 << 16;

fn fault(code: Code) -> Fault {
    Fault::Connection { code }
}

fn offer() -> Settings {
    Settings {
        capacity: 4096,
        size: Some(16_384),
        blocked: 16,
    }
}

fn opened(settings: &Settings) -> Vec<u8> {
    let bytes = Control::open(settings).unwrap();
    assert_eq!(bytes[0], 0x00);
    bytes[1..].to_vec()
}

fn frame(item: &Frame) -> Vec<u8> {
    item.encode().unwrap()
}

fn joined() -> (Control, Control) {
    let mut server = Control::new(LIMIT);
    let mut client = Control::new(LIMIT);
    server.feed(&opened(&offer())).unwrap();
    client.feed(&opened(&Settings::default())).unwrap();
    (server, client)
}

fn control() {
    let mut server = Control::new(LIMIT);
    let notices = server.feed(&opened(&offer())).unwrap();
    assert_eq!(notices, vec![Notice::Settings(offer())]);
    assert_eq!(server.settings(), Some(&offer()));
    let mut client = Control::new(LIMIT);
    let notices = client.feed(&opened(&Settings::default())).unwrap();
    assert_eq!(notices, vec![Notice::Settings(Settings::default())]);
    let mut slow = Control::new(LIMIT);
    let mut notices = Vec::new();
    for byte in opened(&offer()) {
        notices.extend(slow.feed(&[byte]).unwrap());
    }
    assert_eq!(notices, vec![Notice::Settings(offer())]);
    let again = frame(&Frame::Settings(offer()));
    assert_eq!(server.feed(&again), Err(fault(Code::Unexpected)));
    let mut early = Control::new(LIMIT);
    assert_eq!(
        early.feed(&frame(&Frame::Goaway(0))),
        Err(fault(Code::Missing))
    );
    assert_eq!(server.end(), fault(Code::Critical));
}

fn values() {
    let cases = [
        Settings::default(),
        offer(),
        Settings {
            capacity: 0,
            size: Some(0),
            blocked: 1,
        },
        Settings {
            capacity: 1 << 20,
            size: None,
            blocked: 0,
        },
    ];
    for settings in cases {
        let mut peer = Control::new(LIMIT);
        let notices = peer.feed(&opened(&settings)).unwrap();
        assert_eq!(notices, vec![Notice::Settings(settings)]);
    }
    let grease = [0x04, 0x03, 0x40, 0x21, 0x05];
    let mut peer = Control::new(LIMIT);
    let notices = peer.feed(&grease).unwrap();
    assert_eq!(notices, vec![Notice::Settings(Settings::default())]);
    let reserved = [0x04, 0x02, 0x02, 0x00];
    let outcome = Control::new(LIMIT).feed(&reserved);
    assert_eq!(outcome, Err(fault(Code::Setting)));
    let twice = [0x04, 0x04, 0x01, 0x01, 0x01, 0x02];
    assert_eq!(Control::new(LIMIT).feed(&twice), Err(fault(Code::Setting)));
}

fn fields() -> Vec<Field> {
    vec![
        Field::new(b":method", b"GET"),
        Field::new(b":path", b"/index"),
        Field::new(b":scheme", b"http"),
        Field::new(b":authority", b"example.test"),
        Field::secret(b"authorization", b"token"),
    ]
}

fn headers() {
    let block = Encoder::new(true).encode(&fields());
    let mut client = Request::new(LIMIT);
    let mut server = Request::new(LIMIT);
    let wire = client.headers(&block).unwrap();
    let events = server.feed(&wire).unwrap();
    assert_eq!(events, vec![Event::Headers(block.clone())]);
    let peer = Decoder::new(0);
    assert_eq!(peer.decode(&block).unwrap(), fields());
    let mut slow = Request::new(LIMIT);
    let mut events = Vec::new();
    for byte in &wire {
        events.extend(slow.feed(&[*byte]).unwrap());
    }
    assert_eq!(events, vec![Event::Headers(block)]);
}

fn body() {
    let mut client = Request::new(LIMIT);
    let mut server = Request::new(LIMIT);
    let mut wire = client.headers(&[0, 0, 0xd1]).unwrap();
    wire.extend(client.data(b"hello ").unwrap());
    wire.extend(client.data(b"world").unwrap());
    wire.extend(client.headers(&[0, 0, 0xd1]).unwrap());
    client.finish().unwrap();
    let events = server.feed(&wire).unwrap();
    let expected = vec![
        Event::Headers(vec![0, 0, 0xd1]),
        Event::Data(b"hello ".to_vec()),
        Event::Data(b"world".to_vec()),
        Event::Trailers(vec![0, 0, 0xd1]),
    ];
    assert_eq!(events, expected);
    assert_eq!(server.end(), Ok(Event::End));
    assert_eq!(client.data(b"late"), Err(Misuse::Closed));
    let mut early = Request::new(LIMIT);
    assert_eq!(early.data(b"x"), Err(Misuse::Order));
    let stray = frame(&Frame::Data(b"x".to_vec()));
    assert_eq!(
        Request::new(LIMIT).feed(&stray),
        Err(fault(Code::Unexpected))
    );
    let promise = Frame::Promise {
        push: 1,
        block: vec![0, 0],
    };
    let wire = frame(&promise);
    assert_eq!(Request::new(LIMIT).feed(&wire), Err(fault(Code::Id)));
    let mut twice = Request::new(LIMIT);
    twice.headers(&[0, 0]).unwrap();
    twice.data(b"x").unwrap();
    twice.headers(&[0, 0]).unwrap();
    assert_eq!(twice.headers(&[0, 0]), Err(Misuse::Order));
    let mut partial = Request::new(LIMIT);
    partial.feed(&frame(&Frame::Headers(vec![0, 0]))).unwrap();
    let chunked = frame(&Frame::Data(b"abcdef".to_vec()));
    let events = partial.feed(&chunked[..5]).unwrap();
    assert_eq!(events, vec![Event::Data(b"abc".to_vec())]);
    let events = partial.feed(&chunked[5..]).unwrap();
    assert_eq!(events, vec![Event::Data(b"def".to_vec())]);
    let mut cut = Request::new(LIMIT);
    cut.feed(&wire[..wire.len() - 1]).unwrap();
    assert_eq!(cut.end(), Err(fault(Code::Frame)));
}

fn goaway() {
    let (_, mut client) = joined();
    let notices = client.feed(&frame(&Frame::Goaway(8))).unwrap();
    assert_eq!(notices, vec![Notice::Goaway(8)]);
    let notices = client.feed(&frame(&Frame::Goaway(4))).unwrap();
    assert_eq!(notices, vec![Notice::Goaway(4)]);
    assert_eq!(client.feed(&frame(&Frame::Goaway(8))), Err(fault(Code::Id)));
    let (_, mut other) = joined();
    assert_eq!(other.feed(&frame(&Frame::Goaway(5))), Err(fault(Code::Id)));
    let (_, mut client) = joined();
    let mut streams = Streams::new();
    let opened: Vec<u64> = (0..4).map(|_| streams.open().unwrap()).collect();
    assert_eq!(opened, vec![0, 4, 8, 12]);
    let notices = client.feed(&frame(&Frame::Goaway(8))).unwrap();
    assert_eq!(notices, vec![Notice::Goaway(8)]);
    assert_eq!(streams.goaway(8).unwrap(), vec![8, 12]);
    assert_eq!(streams.active(), vec![0, 4]);
    assert_eq!(streams.open(), Err(Going(8)));
}

fn qpack() {
    let mut sender = Sender::new(4096, 8, true);
    let mut decoder = Decoder::new(4096).blocked(8);
    decoder.apply(&sender.capacity(4096).unwrap()).unwrap();
    let wanted = vec![
        Field::new(b":method", b"GET"),
        Field::new(b"x-trace", b"abc123"),
        Field::new(b":authority", b"example.test"),
        Field::secret(b"authorization", b"token"),
    ];
    let mut sizes = Vec::new();
    for stream in [0, 4, 8] {
        let encoded = sender.encode(stream, &wanted).unwrap();
        let used = decoder.apply(&encoded.instructions).unwrap();
        assert_eq!(used, encoded.instructions.len());
        let decoded = decoder.section(stream, &encoded.block).unwrap().unwrap();
        assert_eq!(decoded.fields, wanted);
        if let Some(feedback) = decoded.feedback {
            sender.receive(&feedback.encode().unwrap()).unwrap();
        }
        sizes.push(encoded.block.len() + encoded.instructions.len());
    }
    assert!(sizes[1] < sizes[0]);
    assert_eq!(
        sender.tracker().table().entries(),
        decoder.table().entries()
    );
    assert_eq!(sender.tracker().known(), decoder.known());
    assert!(
        decoder
            .table()
            .entries()
            .iter()
            .all(|entry| entry.name != b"authorization")
    );
}

fn blocked() {
    let mut sender = Sender::new(4096, 1, false);
    let mut decoder = Decoder::new(4096).blocked(1);
    let capacity = sender.capacity(4096).unwrap();
    let held = sender.encode(0, &[Field::new(b"x-a", b"1")]).unwrap();
    let next = sender.encode(4, &[Field::new(b"x-b", b"2")]).unwrap();
    assert_eq!(sender.tracker().blocked(), 1);
    decoder.apply(&capacity).unwrap();
    assert_eq!(decoder.section(0, &held.block), Ok(None));
    assert_eq!(decoder.waiting(), 1);
    let free = decoder.section(4, &next.block).unwrap().unwrap();
    assert_eq!(free.fields, vec![Field::new(b"x-b", b"2")]);
    assert_eq!(decoder.section(8, &held.block), Err(Error::Blocked));
    decoder.apply(&held.instructions).unwrap();
    decoder.apply(&next.instructions).unwrap();
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].stream, 0);
    assert_eq!(ready[0].fields, vec![Field::new(b"x-a", b"1")]);
    assert_eq!(decoder.waiting(), 0);
    let ack = ready[0].feedback.unwrap();
    assert_eq!(ack, Feedback::Acknowledge(0));
    sender.receive(&ack.encode().unwrap()).unwrap();
    assert_eq!(sender.tracker().blocked(), 0);
    let mut sender = Sender::new(4096, 1, false);
    let mut decoder = Decoder::new(4096).blocked(1);
    sender.capacity(4096).unwrap();
    let held = sender.encode(0, &[Field::new(b"x-a", b"1")]).unwrap();
    assert_eq!(decoder.section(0, &held.block), Ok(None));
    let cancel = decoder.cancel(0);
    assert_eq!(decoder.waiting(), 0);
    sender.receive(&cancel.encode().unwrap()).unwrap();
    assert_eq!(sender.tracker().blocked(), 0);
    staged();
}

fn staged() {
    let mut sender = Sender::new(4096, 2, false);
    let mut decoder = Decoder::new(4096).blocked(2);
    decoder.apply(&sender.capacity(4096).unwrap()).unwrap();
    let low = sender.encode(0, &[Field::new(b"x-a", b"1")]).unwrap();
    let high = sender.encode(4, &[Field::new(b"x-b", b"2")]).unwrap();
    assert_eq!(decoder.section(4, &high.block), Ok(None));
    assert_eq!(decoder.section(0, &low.block), Ok(None));
    assert_eq!(decoder.waiting(), 2);
    decoder.apply(&low.instructions).unwrap();
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].stream, 0);
    assert_eq!(decoder.waiting(), 1);
    decoder.apply(&high.instructions).unwrap();
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].stream, 4);
    assert_eq!(ready[0].fields, vec![Field::new(b"x-b", b"2")]);
}
