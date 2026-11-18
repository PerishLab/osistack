use wire::{Error, Prefix, Prefixed, Reader, Writer};

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
