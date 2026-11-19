use h3::{Decoder, Error, Feedback, Instruction, Name};
use wire::Huffman;

fn start(capacity: usize) -> Decoder {
    let mut decoder = Decoder::new(capacity);
    let set = Instruction::Capacity(capacity as u64).encode(None).unwrap();
    decoder.apply(&set).unwrap();
    decoder
}

fn send(decoder: &mut Decoder, instruction: Instruction) -> Result<usize, Error> {
    decoder.apply(&instruction.encode(None).unwrap())
}

fn insert(name: Name, value: &str) -> Instruction {
    Instruction::Insert {
        name,
        value: value.as_bytes().to_vec(),
    }
}

#[test]
fn ceiling() {
    let mut decoder = Decoder::new(100);
    assert_eq!(
        send(&mut decoder, Instruction::Capacity(101)),
        Err(Error::Capacity)
    );
    assert_eq!(send(&mut decoder, Instruction::Capacity(100)), Ok(2));
    assert_eq!(decoder.table().capacity(), 100);
}

#[test]
fn oversize() {
    let mut decoder = start(40);
    let fat = insert(Name::Literal(b"abcdefgh".to_vec()), "xy");
    assert_eq!(send(&mut decoder, fat), Err(Error::Oversize));
    let none = Decoder::new(100).apply(&insert(Name::Static(0), "").encode(None).unwrap());
    assert_eq!(none, Err(Error::Oversize));
}

#[test]
fn statics() {
    let mut decoder = start(200);
    assert_eq!(
        send(&mut decoder, insert(Name::Static(99), "v")),
        Err(Error::Index)
    );
    assert_eq!(send(&mut decoder, insert(Name::Static(98), "v")), Ok(4));
}

#[test]
fn missing() {
    let mut decoder = start(200);
    assert_eq!(
        send(&mut decoder, insert(Name::Dynamic(0), "v")),
        Err(Error::Index)
    );
    assert_eq!(
        send(&mut decoder, Instruction::Duplicate(0)),
        Err(Error::Index)
    );
    send(&mut decoder, insert(Name::Static(1), "/a")).unwrap();
    assert_eq!(
        send(&mut decoder, insert(Name::Dynamic(1), "v")),
        Err(Error::Index)
    );
    assert_eq!(
        send(&mut decoder, Instruction::Duplicate(1)),
        Err(Error::Index)
    );
    assert_eq!(send(&mut decoder, Instruction::Duplicate(0)), Ok(1));
}

#[test]
fn evicted() {
    let mut decoder = start(80);
    send(&mut decoder, insert(Name::Literal(b"a".to_vec()), "")).unwrap();
    send(&mut decoder, insert(Name::Literal(b"b".to_vec()), "")).unwrap();
    send(&mut decoder, insert(Name::Literal(b"c".to_vec()), "")).unwrap();
    assert_eq!(decoder.table().dropped(), 1);
    assert_eq!(decoder.table().get(0), None);
    send(&mut decoder, Instruction::Duplicate(1)).unwrap();
    assert_eq!(decoder.table().get(3).unwrap().name, b"b");
}

#[test]
fn borrowed() {
    let mut decoder = start(66);
    send(&mut decoder, insert(Name::Literal(b"a".to_vec()), "")).unwrap();
    send(&mut decoder, insert(Name::Literal(b"b".to_vec()), "")).unwrap();
    send(&mut decoder, insert(Name::Dynamic(1), "z")).unwrap();
    let held = decoder.table().entries();
    assert_eq!(held.len(), 1);
    assert_eq!(
        (held[0].name.as_slice(), held[0].value.as_slice()),
        (&b"a"[..], &b"z"[..])
    );
    assert_eq!(decoder.table().dropped(), 2);
}

#[test]
fn garbled() {
    let huffman = Huffman::new();
    let plain = [0x41u8, b'a', 0x01, b'z'];
    assert!(matches!(Instruction::decode(&plain, &huffman), Ok(Some(_))));
    let padded = [0x41u8, b'a', 0x81, 0x00];
    assert!(Instruction::decode(&padded, &huffman).is_err());
    assert_eq!(Feedback::decode(&[0x00]), Err(Error::Zero));
}
