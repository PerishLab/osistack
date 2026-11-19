use quic::Number;

#[test]
fn encode() {
    let two = Number::new(0xac5c02, Some(0xabe8b3)).unwrap();
    assert_eq!(
        two,
        Number {
            value: 0x5c02,
            length: 2
        }
    );
    assert_eq!(two.bytes(), vec![0x5c, 0x02]);
    let three = Number::new(0xace8fe, Some(0xabe8b3)).unwrap();
    assert_eq!(
        three,
        Number {
            value: 0xace8fe,
            length: 3
        }
    );
    assert_eq!(three.bytes(), vec![0xac, 0xe8, 0xfe]);
}

#[test]
fn decode() {
    let number = Number {
        value: 0x9b32,
        length: 2,
    };
    assert_eq!(number.restore(Some(0xa82f30ea)), 0xa82f9b32);
}

#[test]
fn wrap() {
    let number = Number {
        value: 0x00,
        length: 1,
    };
    assert_eq!(number.restore(Some(0xff)), 0x100);
    assert_eq!(number.restore(Some(0x7e)), 0x00);
    assert_eq!(number.restore(Some(0x7f)), 0x100);
    assert_eq!(number.restore(Some(0x80)), 0x100);
    let low = Number {
        value: 0xff,
        length: 1,
    };
    assert_eq!(low.restore(Some(0x100)), 0xff);
    assert_eq!(low.restore(None), 0xff);
}
