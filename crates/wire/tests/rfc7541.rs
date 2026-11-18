use wire::{Error, Huffman, Prefix, Prefixed, Reader, Writer};

fn decode(bits: u8, bytes: &[u8]) -> Result<Prefixed, Error> {
    Reader::new(bytes).prefixed(Prefix::new(bits).unwrap())
}

fn encode(bits: u8, high: u8, value: u64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer
        .prefixed(Prefix::new(bits).unwrap(), high, value)
        .unwrap();
    writer.finish()
}

#[test]
fn short() {
    assert_eq!(encode(5, 0, 10), [0x0a]);
    assert_eq!(encode(5, 0xe0, 10), [0xea]);
    assert_eq!(decode(5, &[0x0a]), Ok(Prefixed { high: 0, value: 10 }));
    assert_eq!(
        decode(5, &[0xea]),
        Ok(Prefixed {
            high: 0xe0,
            value: 10
        })
    );
}

#[test]
fn long() {
    assert_eq!(encode(5, 0, 1337), [0x1f, 0x9a, 0x0a]);
    assert_eq!(
        decode(5, &[0x1f, 0x9a, 0x0a]),
        Ok(Prefixed {
            high: 0,
            value: 1337
        })
    );
}

#[test]
fn octet() {
    assert_eq!(encode(8, 0, 42), [0x2a]);
    assert_eq!(decode(8, &[0x2a]), Ok(Prefixed { high: 0, value: 42 }));
}

#[test]
fn malformed() {
    assert_eq!(decode(5, &[0x1f, 0x9a]), Err(Error::Truncated));
    assert_eq!(decode(5, &[0x1f]), Err(Error::Truncated));
    assert_eq!(decode(5, &[]), Err(Error::Truncated));
}

const REQUESTS: [(&str, &str); 4] = [
    ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
    ("no-cache", "a8eb10649cbf"),
    ("custom-key", "25a849e95ba97d7f"),
    ("custom-value", "25a849e95bb8e8b4bf"),
];

const RESPONSES: [(&str, &str); 8] = [
    ("302", "6402"),
    ("private", "aec3771a4b"),
    (
        "Mon, 21 Oct 2013 20:13:21 GMT",
        "d07abe941054d444a8200595040b8166e082a62d1bff",
    ),
    (
        "https://www.example.com",
        "9d29ad171863c78f0b97c8e9ae82ae43d3",
    ),
    ("307", "640eff"),
    (
        "Mon, 21 Oct 2013 20:13:22 GMT",
        "d07abe941054d444a8200595040b8166e084a62d1bff",
    ),
    ("gzip", "9bd9ab"),
    (
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
    ),
];

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn check(vectors: &[(&str, &str)]) {
    let huffman = Huffman::new();
    for (text, hex) in vectors {
        let coded = bytes(hex);
        assert_eq!(huffman.encode(text.as_bytes()), coded, "{text}");
        assert_eq!(huffman.size(text.as_bytes()), coded.len(), "{text}");
        assert_eq!(huffman.decode(&coded).unwrap(), text.as_bytes(), "{text}");
    }
}

#[test]
fn requests() {
    check(&REQUESTS);
}

#[test]
fn responses() {
    check(&RESPONSES);
}
