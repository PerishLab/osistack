use wire::{Error, Reader, Varint, Writer};

fn encode(value: u64) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.varint(Varint::new(value).unwrap());
    writer.finish()
}

fn decode(bytes: &[u8]) -> Result<u64, Error> {
    Reader::new(bytes).varint().map(Varint::get)
}

#[test]
fn longer() {
    assert_eq!(decode(&[0x40, 0x25]), Ok(37));
    assert_eq!(decode(&[0x80, 0x00, 0x00, 0x25]), Ok(37));
    assert_eq!(decode(&[0xc0, 0, 0, 0, 0, 0, 0, 0x25]), Ok(37));
}

#[test]
fn shortest() {
    assert_eq!(encode(37).len(), 1);
    assert_eq!(encode(63).len(), 1);
    assert_eq!(encode(64).len(), 2);
    assert_eq!(encode(16_383).len(), 2);
    assert_eq!(encode(16_384).len(), 4);
    assert_eq!(encode(1_073_741_823).len(), 4);
    assert_eq!(encode(1_073_741_824).len(), 8);
}

#[test]
fn edges() {
    let edges = [
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        (1 << 62) - 1,
    ];
    for value in edges {
        assert_eq!(decode(&encode(value)), Ok(value));
    }
}

#[test]
fn truncated() {
    assert_eq!(decode(&[]), Err(Error::Truncated));
    assert_eq!(decode(&[0x40]), Err(Error::Truncated));
    assert_eq!(decode(&[0x80, 0, 0]), Err(Error::Truncated));
    assert_eq!(decode(&[0xc0, 0, 0, 0, 0, 0, 0]), Err(Error::Truncated));
}

#[test]
fn limit() {
    assert_eq!(Varint::new(1 << 62), Err(Error::Range));
    assert_eq!(Varint::new(u64::MAX), Err(Error::Range));
    assert_eq!(
        Varint::new((1 << 62) - 1).map(Varint::get),
        Ok((1 << 62) - 1)
    );
}

#[test]
fn consumed() {
    let mut reader = Reader::new(&[0x7b, 0xbd, 0x25, 0xff]);
    assert_eq!(reader.varint().map(Varint::get), Ok(15_293));
    assert_eq!(reader.varint().map(Varint::get), Ok(37));
    assert_eq!(reader.left(), 1);
}

#[test]
fn position() {
    let mut reader = Reader::new(&[0x25, 0x80, 0x00]);
    assert_eq!(reader.varint().map(Varint::get), Ok(37));
    assert_eq!(reader.varint(), Err(Error::Truncated));
}
