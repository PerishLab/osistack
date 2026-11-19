use crate::support::*;
use h3::{Decoded, Decoder, Feedback, Sender};

const CAPACITY: &str = "3fbd01";
const FIRST: &str = "c00f 7777772e6578616d706c652e636f6d c10c 2f73616d706c652f70617468";
const CUSTOM: &str = "4a 637573746f6d2d6b6579 0c 637573746f6d2d76616c7565";

#[test]
fn replay() {
    let mut sender = Sender::new(220, 1, false);
    let mut decoder = Decoder::new(220).blocked(1);
    let setup = sender.capacity(220).unwrap();
    assert_eq!(setup, hex(CAPACITY));
    decoder.apply(&setup).unwrap();
    let pair = vec![
        field(":authority", "www.example.com"),
        field(":path", "/sample/path"),
    ];
    let one = sender.encode(4, &pair).unwrap();
    assert_eq!(one.instructions, hex(FIRST));
    decoder.apply(&one.instructions).unwrap();
    assert_eq!(decoder.table().size(), 106);
    let decoded = decoder.section(4, &one.block).unwrap().unwrap();
    let expect = Decoded {
        stream: 4,
        fields: pair,
        feedback: Some(Feedback::Acknowledge(4)),
    };
    assert_eq!(decoded, expect);
    let wire = decoded.feedback.unwrap().encode().unwrap();
    assert_eq!(wire, hex("84"));
    assert_eq!(sender.receive(&wire), Ok(1));
    assert_eq!(sender.tracker().known(), 2);
    let mixed = vec![
        field(":authority", "www.example.com"),
        field(":path", "/"),
        field("custom-key", "custom-value"),
    ];
    let two = sender.encode(8, &mixed).unwrap();
    assert_eq!(two.instructions, hex(CUSTOM));
    decoder.apply(&two.instructions).unwrap();
    assert_eq!(decoder.table().size(), 160);
    let bump = decoder.increment().unwrap().encode().unwrap();
    assert_eq!(bump, hex("01"));
    assert_eq!(sender.receive(&bump), Ok(1));
    assert_eq!(sender.tracker().known(), 3);
    assert_eq!(sender.tracker().blocked(), 0);
    let decoded = decoder.section(8, &two.block).unwrap().unwrap();
    assert_eq!(decoded.fields, mixed);
    assert_eq!(decoded.feedback, Some(Feedback::Acknowledge(8)));
    assert_eq!(sender.receive(&ack(8)), Ok(1));
    assert_eq!(sender.tracker().known(), 3);
    assert_eq!(sender.tracker().blocked(), 0);
}
