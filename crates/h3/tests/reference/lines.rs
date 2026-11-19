use crate::support::*;
use h3::{Encoder, Field};

const ENTRIES: [(&str, &str); 2] = [("x-a", "1"), ("x-b", "2")];

fn write(base: u64, fields: &[Field]) -> Vec<u8> {
    let table = table(220, &ENTRIES);
    Encoder::new(false).reference(&table, base, fields).unwrap()
}

fn read(bytes: &[u8]) -> Vec<Field> {
    let mut decoder = decoder(220, 0, &ENTRIES);
    decoder.section(0, bytes).unwrap().unwrap().fields
}

#[test]
fn relative() {
    let bytes = write(2, &[field("x-b", "2"), field("x-a", "1")]);
    assert_eq!(bytes, hex("0300 80 81"));
    assert_eq!(read(&bytes), [field("x-b", "2"), field("x-a", "1")]);
}

#[test]
fn after() {
    let bytes = write(0, &[field("x-b", "2"), field("x-a", "1")]);
    assert_eq!(bytes, hex("0381 11 10"));
    assert_eq!(read(&bytes), [field("x-b", "2"), field("x-a", "1")]);
}

#[test]
fn between() {
    let bytes = write(1, &[field("x-a", "1"), field("x-b", "2")]);
    assert_eq!(bytes, hex("0380 80 10"));
    assert_eq!(read(&bytes), [field("x-a", "1"), field("x-b", "2")]);
}

#[test]
fn behind() {
    let bytes = write(2, &[field("x-b", "9")]);
    assert_eq!(bytes, hex("0300 40 01 39"));
    assert_eq!(read(&bytes), [field("x-b", "9")]);
}

#[test]
fn ahead() {
    let bytes = write(0, &[field("x-b", "9")]);
    assert_eq!(bytes, hex("0381 01 01 39"));
    assert_eq!(read(&bytes), [field("x-b", "9")]);
}

#[test]
fn hidden() {
    let behind = write(2, &[secret("x-b", "2")]);
    assert_eq!(behind, hex("0300 60 01 32"));
    assert_eq!(read(&behind), [secret("x-b", "2")]);
    let ahead = write(0, &[secret("x-b", "9")]);
    assert_eq!(ahead, hex("0381 09 01 39"));
    assert_eq!(read(&ahead), [secret("x-b", "9")]);
}

#[test]
fn fixed() {
    let fields = [
        field(":method", "GET"),
        field(":path", "/x"),
        secret("cookie", "a=b"),
        field("x-new", "v"),
        secret("x-hid", "w"),
    ];
    let bytes = write(2, &fields);
    assert_eq!(bytes[..2], hex("0000")[..]);
    assert_eq!(read(&bytes), fields);
}

#[test]
fn newest() {
    let entries = [("x-a", "1"), ("x-a", "2"), ("x-a", "1")];
    let table = table(220, &entries);
    let bytes = Encoder::new(false)
        .reference(&table, 3, &[field("x-a", "1")])
        .unwrap();
    assert_eq!(bytes, hex("0400 80"));
}

#[test]
fn huffman() {
    let table = table(220, &ENTRIES);
    let fields = [field("x-b", "value"), field("x-c", "other")];
    let bytes = Encoder::new(true).reference(&table, 1, &fields).unwrap();
    assert_eq!(read(&bytes), fields);
}

#[test]
fn every() {
    let fields = [
        field("x-a", "1"),
        field("x-b", "9"),
        secret("x-a", "1"),
        field("x-b", "2"),
        field(":method", "GET"),
        field("x-c", "3"),
    ];
    for base in 0..=2 {
        assert_eq!(read(&write(base, &fields)), fields, "{base}");
    }
}
