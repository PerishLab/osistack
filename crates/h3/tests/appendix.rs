use h3::{Decoder, Feedback, Field, Instruction, Name};
use wire::Huffman;

fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

fn parse(bytes: &[u8]) -> Vec<Instruction> {
    let huffman = Huffman::new();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some((instruction, used)) = Instruction::decode(&bytes[at..], &huffman).unwrap() {
        found.push(instruction);
        at += used;
    }
    assert_eq!(at, bytes.len());
    found
}

fn literal(name: &str) -> Name {
    Name::Literal(name.as_bytes().to_vec())
}

fn insert(name: Name, value: &str) -> Instruction {
    Instruction::Insert {
        name,
        value: value.as_bytes().to_vec(),
    }
}

fn check(decoder: &Decoder, size: usize, dropped: u64, held: &[(&str, &str)]) {
    let table = decoder.table();
    assert_eq!(table.size(), size);
    assert_eq!(table.dropped(), dropped);
    assert_eq!(table.inserted(), dropped + held.len() as u64);
    let want: Vec<Field> = held
        .iter()
        .map(|(name, value)| Field::new(name.as_bytes(), value.as_bytes()))
        .collect();
    assert_eq!(table.entries(), want);
}

fn step(decoder: &mut Decoder, text: &str, expected: &[Instruction]) {
    let bytes = hex(text);
    assert_eq!(parse(&bytes), expected);
    let mut rebuilt = Vec::new();
    for instruction in expected {
        rebuilt.extend(instruction.encode(None).unwrap());
    }
    assert_eq!(rebuilt, bytes);
    assert_eq!(decoder.apply(&bytes).unwrap(), bytes.len());
}

#[test]
fn sequence() {
    let mut decoder = Decoder::new(220);
    step(
        &mut decoder,
        "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468",
        &[
            Instruction::Capacity(220),
            insert(Name::Static(0), "www.example.com"),
            insert(Name::Static(1), "/sample/path"),
        ],
    );
    check(
        &decoder,
        106,
        0,
        &[(":authority", "www.example.com"), (":path", "/sample/path")],
    );
    step(
        &mut decoder,
        "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565",
        &[insert(literal("custom-key"), "custom-value")],
    );
    check(
        &decoder,
        160,
        0,
        &[
            (":authority", "www.example.com"),
            (":path", "/sample/path"),
            ("custom-key", "custom-value"),
        ],
    );
    step(&mut decoder, "02", &[Instruction::Duplicate(2)]);
    check(
        &decoder,
        217,
        0,
        &[
            (":authority", "www.example.com"),
            (":path", "/sample/path"),
            ("custom-key", "custom-value"),
            (":authority", "www.example.com"),
        ],
    );
    step(
        &mut decoder,
        "810d 6375 7374 6f6d 2d76 616c 7565 32",
        &[insert(Name::Dynamic(1), "custom-value2")],
    );
    check(
        &decoder,
        215,
        1,
        &[
            (":path", "/sample/path"),
            ("custom-key", "custom-value"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value2"),
        ],
    );
}

#[test]
fn feedback() {
    let cases = [
        ("84", Feedback::Acknowledge(4)),
        ("01", Feedback::Increment(1)),
        ("48", Feedback::Cancel(8)),
    ];
    for (text, expected) in cases {
        let bytes = hex(text);
        assert_eq!(
            Feedback::decode(&bytes).unwrap(),
            Some((expected, bytes.len()))
        );
        assert_eq!(expected.encode().unwrap(), bytes);
    }
}

#[test]
fn shortened() {
    let bytes = hex("c00f 7777 772e 6578 616d 706c 652e 636f 6d");
    let huffman = Huffman::new();
    for cut in 0..bytes.len() {
        assert_eq!(Instruction::decode(&bytes[..cut], &huffman).unwrap(), None);
    }
    let mut decoder = Decoder::new(220);
    decoder.apply(&hex("3fbd01")).unwrap();
    assert_eq!(decoder.apply(&bytes[..6]).unwrap(), 0);
    assert_eq!(decoder.apply(&bytes).unwrap(), bytes.len());
}
