use crate::support::*;
use h3::{Decoded, Decoder, Encoder, Feedback};

const FIRST: &str = "3fbd01 c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468";
const CUSTOM: &str = "4a 637573746f6d2d6b6579 0c 637573746f6d2d76616c7565";
const NINTH: &str = "0381 10 11";
const EIGHTH: &str = "0500 80 c1 81";

fn pair() -> Vec<h3::Field> {
    vec![
        field(":authority", "www.example.com"),
        field(":path", "/sample/path"),
    ]
}

fn mixed() -> Vec<h3::Field> {
    vec![
        field(":authority", "www.example.com"),
        field(":path", "/"),
        field("custom-key", "custom-value"),
    ]
}

fn bytes(feedback: Feedback) -> Vec<u8> {
    feedback.encode().unwrap()
}

#[test]
fn sections() {
    let mut decoder = Decoder::new(220).blocked(1);
    let first = hex(FIRST);
    assert_eq!(decoder.apply(&first).unwrap(), first.len());
    assert_eq!(decoder.table().size(), 106);
    let decoded = decoder.section(4, &hex(NINTH)).unwrap().unwrap();
    let expect = Decoded {
        stream: 4,
        fields: pair(),
        feedback: Some(Feedback::Acknowledge(4)),
    };
    assert_eq!(decoded, expect);
    assert_eq!(bytes(Feedback::Acknowledge(4)), hex("84"));
    assert_eq!(decoder.known(), 2);
    assert_eq!(decoder.increment(), None);
}

#[test]
fn speculative() {
    let mut decoder = decoder(
        220,
        1,
        &[(":authority", "www.example.com"), (":path", "/sample/path")],
    );
    decoder.section(4, &hex(NINTH)).unwrap();
    let custom = hex(CUSTOM);
    assert_eq!(decoder.apply(&custom).unwrap(), custom.len());
    assert_eq!(decoder.table().size(), 160);
    let feedback = decoder.increment().unwrap();
    assert_eq!(bytes(feedback), hex("01"));
    assert_eq!(decoder.known(), 3);
    assert_eq!(decoder.increment(), None);
}

#[test]
fn cancelled() {
    let entries = [
        (":authority", "www.example.com"),
        (":path", "/sample/path"),
        ("custom-key", "custom-value"),
    ];
    let mut decoder = decoder(220, 1, &entries);
    assert_eq!(decoder.section(8, &hex(EIGHTH)).unwrap(), None);
    assert_eq!(decoder.waiting(), 1);
    let feedback = decoder.cancel(8);
    assert_eq!(bytes(feedback), hex("48"));
    assert_eq!(decoder.waiting(), 0);
    assert_eq!(decoder.apply(&hex("02")).unwrap(), 1);
    assert_eq!(decoder.table().size(), 217);
    let decoded = decoder.section(8, &hex(EIGHTH)).unwrap().unwrap();
    assert_eq!(decoded.fields, mixed());
    assert_eq!(bytes(decoded.feedback.unwrap()), hex("88"));
}

#[test]
fn released() {
    let entries = [
        (":authority", "www.example.com"),
        (":path", "/sample/path"),
        ("custom-key", "custom-value"),
    ];
    let mut decoder = decoder(220, 1, &entries);
    assert_eq!(decoder.section(8, &hex(EIGHTH)).unwrap(), None);
    assert!(decoder.ready().unwrap().is_empty());
    decoder.apply(&hex("02")).unwrap();
    let ready = decoder.ready().unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].stream, 8);
    assert_eq!(ready[0].fields, mixed());
    assert_eq!(ready[0].feedback, Some(Feedback::Acknowledge(8)));
    assert_eq!(decoder.waiting(), 0);
    assert_eq!(decoder.known(), 4);
}

#[test]
fn evicting() {
    let entries = [
        (":authority", "www.example.com"),
        (":path", "/sample/path"),
        ("custom-key", "custom-value"),
    ];
    let mut decoder = decoder(220, 1, &entries);
    decoder.apply(&hex("02")).unwrap();
    decoder
        .apply(&hex("810d 637573746f6d2d76616c756532"))
        .unwrap();
    assert_eq!(decoder.table().size(), 215);
    assert_eq!(decoder.table().dropped(), 1);
    let last = decoder.table().get(4).unwrap();
    assert_eq!(last, &field("custom-key", "custom-value2"));
}

#[test]
fn writing() {
    let encoder = Encoder::new(false);
    let ninth = table(
        220,
        &[(":authority", "www.example.com"), (":path", "/sample/path")],
    );
    assert_eq!(encoder.reference(&ninth, 0, &pair()).unwrap(), hex(NINTH));
    let eighth = table(
        220,
        &[
            (":authority", "www.example.com"),
            (":path", "/sample/path"),
            ("custom-key", "custom-value"),
            (":authority", "www.example.com"),
        ],
    );
    assert_eq!(
        encoder.reference(&eighth, 4, &mixed()).unwrap(),
        hex(EIGHTH)
    );
}

#[test]
fn literal() {
    let encoder = Encoder::new(false);
    let empty = table(0, &[]);
    let bytes = encoder
        .reference(&empty, 0, &[field(":path", "/index.html")])
        .unwrap();
    assert_eq!(bytes, hex("0000 510b 2f696e6465782e68746d6c"));
    let mut decoder = Decoder::new(0);
    assert_eq!(decoder.section(0, &bytes).unwrap().unwrap().feedback, None);
}
