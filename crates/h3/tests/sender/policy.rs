use crate::support::*;
use h3::{Decoder, Dynamic, Encoder, Error, Instruction, Name, Sender};

fn ready(maximum: usize, blocked: usize, capacity: usize) -> Sender {
    let mut sender = Sender::new(maximum, blocked, false);
    sender.capacity(capacity).unwrap();
    sender
}

#[test]
fn plain() {
    let mut sender = Sender::new(220, 1, false);
    let fields = [field("x-a", "1"), field(":path", "/")];
    let encoded = sender.encode(4, &fields).unwrap();
    assert!(encoded.instructions.is_empty());
    assert_eq!(encoded.block, empty(&fields));
    assert_eq!(sender.tracker().table().inserted(), 0);
}

#[test]
fn statics() {
    let mut sender = ready(220, 1, 220);
    let fields = [field(":method", "GET"), field(":path", "/")];
    let encoded = sender.encode(4, &fields).unwrap();
    assert!(encoded.instructions.is_empty());
    assert_eq!(sender.tracker().table().inserted(), 0);
    assert_eq!(encoded.block, empty(&fields));
}

#[test]
fn fresh() {
    let mut sender = ready(220, 0, 220);
    let fields = [field("x-a", "1")];
    let encoded = sender.encode(4, &fields).unwrap();
    assert_eq!(encoded.instructions, put(literal("x-a"), "1"));
    assert_eq!(sender.tracker().table().inserted(), 1);
    assert_eq!(encoded.block, empty(&fields));
    assert_eq!(sender.tracker().outstanding(4), 0);
    sender.receive(&increment(1)).unwrap();
    let again = sender.encode(8, &fields).unwrap();
    assert!(again.instructions.is_empty());
    assert_eq!(sender.tracker().outstanding(8), 1);
    assert!(sender.tracker().held(0));
}

#[test]
fn cited() {
    let mut sender = ready(220, 1, 220);
    let fields = [field("x-a", "1")];
    let encoded = sender.encode(4, &fields).unwrap();
    assert_eq!(sender.tracker().outstanding(4), 1);
    assert_eq!(sender.tracker().blocked(), 1);
    assert_ne!(encoded.block[0], 0);
    let mut decoder = Decoder::new(220).blocked(1);
    let mut setup = Instruction::Capacity(220).encode(None).unwrap();
    setup.extend(&encoded.instructions);
    decoder.apply(&setup).unwrap();
    let decoded = decoder.section(4, &encoded.block).unwrap().unwrap();
    assert_eq!(decoded.fields, fields.to_vec());
}

#[test]
fn private() {
    let mut sender = ready(220, 1, 220);
    let plain = [field("authorization", "token")];
    sender.encode(4, &plain).unwrap();
    sender.receive(&ack(4)).unwrap();
    let hidden = [secret("authorization", "token")];
    let encoded = sender.encode(8, &hidden).unwrap();
    assert!(encoded.instructions.is_empty());
    assert_eq!(sender.tracker().table().inserted(), 1);
    let table = sender.tracker().table();
    let expected = Encoder::new(false)
        .reference(table, table.inserted(), &hidden)
        .unwrap();
    assert_eq!(encoded.block, expected);
    let mut fresh = ready(220, 1, 220);
    let alone = fresh.encode(4, &hidden).unwrap();
    assert!(alone.instructions.is_empty());
    assert_eq!(fresh.tracker().table().inserted(), 0);
    assert_eq!(alone.block, empty(&hidden));
}

#[test]
fn oversize() {
    let mut sender = ready(220, 1, 70);
    let fields = [field("x-big", &"v".repeat(100))];
    let encoded = sender.encode(4, &fields).unwrap();
    assert!(encoded.instructions.is_empty());
    assert_eq!(sender.tracker().table().inserted(), 0);
    assert_eq!(encoded.block, empty(&fields));
}

#[test]
fn repeat() {
    let mut sender = ready(220, 1, 220);
    let fields = [field("x-a", "1"), field("x-a", "1")];
    let encoded = sender.encode(4, &fields).unwrap();
    assert_eq!(encoded.instructions, put(literal("x-a"), "1"));
    assert_eq!(sender.tracker().table().inserted(), 1);
}

#[test]
fn names() {
    let mut sender = ready(220, 0, 220);
    let one = sender.encode(0, &[field(":authority", "a.com")]).unwrap();
    assert_eq!(one.instructions, put(Name::Static(0), "a.com"));
    let two = sender.encode(4, &[field("x-k", "1")]).unwrap();
    assert_eq!(two.instructions, put(literal("x-k"), "1"));
    let three = sender.encode(8, &[field("x-k", "2")]).unwrap();
    assert_eq!(three.instructions, put(Name::Dynamic(0), "2"));
}

#[test]
fn doomed() {
    let mut sender = ready(220, 0, 36);
    sender.encode(0, &[field("x-k", "1")]).unwrap();
    let next = sender.encode(4, &[field("x-k", "2")]).unwrap();
    assert_eq!(next.instructions, put(literal("x-k"), "2"));
    assert_eq!(sender.tracker().table().dropped(), 1);
    let table: &Dynamic = sender.tracker().table();
    assert_eq!(table.get(1), Some(&field("x-k", "2")));
}

#[test]
fn capacity() {
    let mut sender = Sender::new(220, 1, false);
    let bytes = sender.capacity(220).unwrap();
    assert_eq!(bytes, Instruction::Capacity(220).encode(None).unwrap());
    assert_eq!(bytes, hex("3fbd01"));
    assert_eq!(sender.capacity(221), Err(Error::Capacity));
    assert_eq!(sender.tracker().table().capacity(), 220);
}
