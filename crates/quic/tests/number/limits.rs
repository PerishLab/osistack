use quic::{Error, Number};

#[test]
fn edge() {
    let one = Number::new(1000, Some(873)).unwrap();
    assert_eq!(
        one,
        Number {
            value: 232,
            length: 1
        }
    );
    let two = Number::new(1000, Some(872)).unwrap();
    assert_eq!(
        two,
        Number {
            value: 1000,
            length: 2
        }
    );
    assert_eq!(
        Number::new(0, None),
        Ok(Number {
            value: 0,
            length: 1
        })
    );
    assert_eq!(Number::new(126, None).unwrap().length, 1);
    assert_eq!(Number::new(127, None).unwrap().length, 2);
}

#[test]
fn bounds() {
    let top = (1u64 << 62) - 1;
    assert_eq!(Number::new(top, Some(top - 1)).unwrap().length, 1);
    assert_eq!(Number::new(1 << 62, None), Err(Error::Number));
    assert_eq!(Number::new(5, Some(5)), Err(Error::Number));
    assert_eq!(Number::new(5, Some(6)), Err(Error::Number));
    assert_eq!(Number::new(1 << 40, Some(0)), Err(Error::Number));
    let widest = (1u64 << 31) - 1;
    assert_eq!(Number::new(widest, Some(0)).unwrap().length, 4);
    assert_eq!(Number::new(widest + 1, Some(0)), Err(Error::Number));
}

#[test]
fn reserved() {
    for first in [0xc4, 0xc8, 0xcc, 0x48, 0x50, 0x58] {
        assert_eq!(
            Number::read(first, &[0; 4]),
            Err(Error::Reserved),
            "{first:x}"
        );
    }
    for first in [0xc0, 0xc3, 0x40, 0x44, 0x63, 0x67] {
        assert!(Number::read(first, &[0; 4]).is_ok(), "{first:x}");
    }
}

#[test]
fn length() {
    let bytes = [1, 2, 3, 4];
    for (first, length, value) in [
        (0xc0u8, 1, 1u32),
        (0xc1, 2, 0x0102),
        (0xc2, 3, 0x010203),
        (0xc3, 4, 0x01020304),
        (0x41, 2, 0x0102),
    ] {
        assert_eq!(Number::read(first, &bytes), Ok(Number { value, length }));
    }
}

#[test]
fn short() {
    let truncated = Err(Error::Wire(wire::Error::Truncated));
    assert_eq!(Number::read(0xc3, &[0, 0, 0]), truncated);
    assert_eq!(Number::read(0xc0, &[]), truncated);
}
