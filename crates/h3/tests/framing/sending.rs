use crate::support::*;
use h3::{Decoder, Encoder, Event, Field, Misuse, Request};

#[test]
fn outgoing() {
    let mut request = Request::new(64);
    assert_eq!(
        request.headers(&[1, 2, 3]).unwrap(),
        bytes("01 03 01 02 03")
    );
    assert_eq!(request.data(b"hi").unwrap(), bytes("00 02 68 69"));
    let big = request.data(&vec![7; 100_000]).unwrap();
    assert_eq!(&big[..5], &bytes("00 80 01 86 a0")[..]);
    assert_eq!(big.len(), 100_005);
    assert_eq!(request.headers(&[9]).unwrap(), bytes("01 01 09"));
    assert_eq!(request.finish(), Ok(()));
}

#[test]
fn order() {
    let mut first = Request::new(64);
    assert_eq!(first.data(b"d"), Err(Misuse::Order));
    first.headers(b"h").unwrap();
    first.headers(b"t").unwrap();
    assert_eq!(first.data(b"d"), Err(Misuse::Order));
    assert_eq!(first.headers(b"u"), Err(Misuse::Order));
    let mut body = Request::new(64);
    body.headers(b"h").unwrap();
    body.data(b"d").unwrap();
    body.data(b"e").unwrap();
    body.headers(b"t").unwrap();
    assert_eq!(body.data(b"d"), Err(Misuse::Order));
    assert_eq!(body.headers(b"u"), Err(Misuse::Order));
}

#[test]
fn closing() {
    let mut empty = Request::new(64);
    assert_eq!(empty.finish(), Err(Misuse::Empty));
    empty.headers(b"h").unwrap();
    empty.finish().unwrap();
    assert_eq!(empty.finish(), Err(Misuse::Closed));
    assert_eq!(empty.headers(b"t"), Err(Misuse::Closed));
    assert_eq!(empty.data(b"d"), Err(Misuse::Closed));
    let mut done = Request::new(64);
    done.headers(b"h").unwrap();
    done.headers(b"t").unwrap();
    done.finish().unwrap();
    assert_eq!(done.data(b"d"), Err(Misuse::Closed));
}

#[test]
fn exchange() {
    let mut sender = Request::new(64);
    let mut receiver = Request::new(64);
    let payload = vec![3; 100_000];
    let mut wire = sender.headers(b"head").unwrap();
    wire.extend(sender.data(&payload).unwrap());
    wire.extend(sender.headers(b"tail").unwrap());
    sender.finish().unwrap();
    let events = receiver.feed(&wire).unwrap();
    let expected = vec![
        Event::Headers(b"head".to_vec()),
        Event::Data(payload),
        Event::Trailers(b"tail".to_vec()),
    ];
    assert_eq!(merged(events), expected);
    assert_eq!(receiver.end(), Ok(Event::End));
}

#[test]
fn composed() {
    let fields = vec![
        Field::new(b":method", b"GET"),
        Field::new(b":scheme", b"https"),
        Field::new(b":authority", b"example.com"),
        Field::new(b":path", b"/index.html"),
        Field::new(b"x-key", b"value"),
    ];
    let trailers = vec![Field::new(b"x-sum", b"1")];
    let encoder = Encoder::new(true);
    let (head, tail) = (encoder.encode(&fields), encoder.encode(&trailers));
    let mut sender = Request::new(64);
    let mut wire = sender.headers(&head).unwrap();
    wire.extend(sender.data(b"body").unwrap());
    wire.extend(sender.headers(&tail).unwrap());
    let events = Request::new(1 << 12).feed(&wire).unwrap();
    let decoder = Decoder::new(0);
    let (Event::Headers(first), Event::Trailers(last)) = (&events[0], &events[2]) else {
        panic!("{events:?}");
    };
    assert_eq!(decoder.decode(first).unwrap(), fields);
    assert_eq!(decoder.decode(last).unwrap(), trailers);
}

#[test]
fn blocked() {
    let block = bytes("03 81 10 11");
    let mut sender = Request::new(64);
    let wire = sender.headers(&block).unwrap();
    let events = Request::new(64).feed(&wire).unwrap();
    assert_eq!(events, vec![Event::Headers(block.clone())]);
    let mut decoder = Decoder::new(4096).blocked(1);
    assert_eq!(decoder.section(4, &block), Ok(None));
    assert_eq!(decoder.waiting(), 1);
}
