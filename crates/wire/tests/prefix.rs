use wire::{Error, Prefix, Prefixed, Reader, Writer};

fn read(bits: u8, bytes: &[u8]) -> Result<Prefixed, Error> {
    Reader::new(bytes).prefixed(Prefix::new(bits).unwrap())
}

fn write(bits: u8, high: u8, value: u64) -> Result<Vec<u8>, Error> {
    let mut writer = Writer::new();
    writer.prefixed(Prefix::new(bits).unwrap(), high, value)?;
    Ok(writer.finish())
}

#[test]
fn width() {
    assert_eq!(Prefix::new(0), Err(Error::Range));
    assert_eq!(Prefix::new(9), Err(Error::Range));
    for bits in 1..=8 {
        assert_eq!(Prefix::new(bits).unwrap().bits(), bits);
    }
}

#[test]
fn boundary() {
    assert_eq!(write(5, 0, 30).unwrap(), [30]);
    assert_eq!(write(5, 0, 31).unwrap(), [0x1f, 0x00]);
    assert_eq!(write(5, 0, 32).unwrap(), [0x1f, 0x01]);
    assert_eq!(write(1, 0, 0).unwrap(), [0x00]);
    assert_eq!(write(1, 0, 1).unwrap(), [0x01, 0x00]);
    assert_eq!(write(8, 0, 254).unwrap(), [0xfe]);
    assert_eq!(write(8, 0, 255).unwrap(), [0xff, 0x00]);
}

#[test]
fn round() {
    let values = [0, 1, 30, 31, 127, 128, 1337, 16_383, 1 << 32, u64::MAX];
    for bits in 1..=8u8 {
        let high = !(u8::MAX >> (8 - bits)) & 0xa0;
        for value in values {
            let bytes = write(bits, high, value).unwrap();
            let mut reader = Reader::new(&bytes);
            let got = reader.prefixed(Prefix::new(bits).unwrap()).unwrap();
            assert_eq!(got, Prefixed { high, value });
            assert_eq!(reader.left(), 0);
        }
    }
}

#[test]
fn overlap() {
    assert_eq!(write(5, 0x01, 10), Err(Error::Range));
    assert_eq!(write(8, 0x01, 10), Err(Error::Range));
    assert_eq!(write(5, 0x20, 10).unwrap(), [0x2a]);
}

#[test]
fn consumed() {
    let mut reader = Reader::new(&[0x1f, 0x9a, 0x0a, 0x2a]);
    let prefix = Prefix::new(5).unwrap();
    assert_eq!(reader.prefixed(prefix).map(|p| p.value), Ok(1337));
    assert_eq!(reader.at(), 3);
    assert_eq!(
        reader.prefixed(Prefix::new(8).unwrap()).map(|p| p.value),
        Ok(42)
    );
}

#[test]
fn padded() {
    assert_eq!(read(5, &[0x1f, 0x80, 0x00]).map(|p| p.value), Ok(31));
    let mut long = vec![0x1f];
    long.extend([0x80; 10]);
    long.push(0x00);
    assert_eq!(read(5, &long).map(|p| p.value), Ok(31));
}

#[test]
fn overflow() {
    let mut bytes = vec![0x1f];
    bytes.extend([0xff; 9]);
    bytes.push(0x02);
    assert_eq!(read(5, &bytes), Err(Error::Range));
    let mut far = vec![0x1f];
    far.extend([0x80; 10]);
    far.push(0x01);
    assert_eq!(read(5, &far), Err(Error::Range));
}

#[test]
fn maximum() {
    let mut bytes = vec![0x1f];
    bytes.extend([0xff; 8]);
    bytes.extend([0x7f, 0x00]);
    assert_eq!(read(5, &bytes).map(|p| p.value), Ok(31 + (1 << 63) - 1));
}

#[test]
fn trips() {
    let mut values: Vec<u64> = (0..400).collect();
    values.extend([
        511,
        512,
        16_383,
        16_384,
        1 << 32,
        (1 << 32) - 1,
        (1 << 63) - 1,
        u64::MAX,
    ]);
    for bits in 1..=8u8 {
        let high = !(u8::MAX >> (8 - bits)) & 0xa0;
        for value in &values {
            let bytes = write(bits, high, *value).unwrap();
            let mut reader = Reader::new(&bytes);
            let got = reader.prefixed(Prefix::new(bits).unwrap()).unwrap();
            assert_eq!(
                got,
                Prefixed {
                    high,
                    value: *value
                },
                "{bits} {value}"
            );
            assert_eq!(reader.left(), 0);
            for cut in 0..bytes.len() {
                assert_eq!(
                    read(bits, &bytes[..cut]),
                    Err(Error::Truncated),
                    "{bits} {value} {cut}"
                );
            }
        }
    }
}
