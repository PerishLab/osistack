use wire::{Error, Reader, Varint, Writer};

fn decode(bytes: &[u8]) -> Result<u64, Error> {
    Reader::new(bytes).varint().map(Varint::get)
}

#[test]
fn decoded() {
    let cases: [(&[u8], u64); 5] = [
        (
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            151_288_809_941_952_652,
        ),
        (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
        (&[0x7b, 0xbd], 15_293),
        (&[0x25], 37),
        (&[0x40, 0x25], 37),
    ];
    for (bytes, value) in cases {
        assert_eq!(decode(bytes), Ok(value));
    }
}

#[test]
fn encoded() {
    let mut writer = Writer::new();
    writer.varint(Varint::new(37).unwrap());
    assert_eq!(writer.finish(), [0x25]);
}

#[test]
fn malformed() {
    assert_eq!(decode(&[0xc2, 0x19, 0x7c]), Err(Error::Truncated));
    assert_eq!(decode(&[0x9d, 0x7f]), Err(Error::Truncated));
    assert_eq!(decode(&[]), Err(Error::Truncated));
}
