use h2::{Decoder, Encoder, Error, Header};
use wire::Error as Wire;

fn decode(limit: usize, block: &[u8]) -> Result<Vec<Header>, Error> {
    Decoder::new(limit).decode(block)
}

#[test]
fn zero() {
    assert_eq!(decode(4096, &[0x80]), Err(Error::Index));
}

#[test]
fn beyond() {
    assert_eq!(decode(4096, &[0xbe]), Err(Error::Index));
    assert_eq!(decode(4096, &[0x7e, 0x01, b'x']), Err(Error::Index));
    assert_eq!(decode(4096, &[0x0f, 0x2f, 0x01, b'x']), Err(Error::Index));
    assert_eq!(
        decode(4096, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
        Err(Error::Index)
    );
}

#[test]
fn largest() {
    assert_eq!(decode(4096, &[0x81]).unwrap().len(), 1);
    assert_eq!(decode(4096, &[0xbd]).unwrap().len(), 1);
    assert_eq!(decode(4096, &[0xbe]), Err(Error::Index));
}

#[test]
fn limit() {
    assert_eq!(decode(100, &[0x3f, 0xa9, 0x01]), Err(Error::Size));
    assert_eq!(decode(100, &[0x3f, 0x45]), Ok(Vec::new()));
    assert_eq!(decode(100, &[0x3f, 0x46]), Err(Error::Size));
    assert_eq!(decode(0, &[0x21]), Err(Error::Size));
}

#[test]
fn position() {
    assert_eq!(decode(4096, &[0x82, 0x20]), Err(Error::Size));
    assert_eq!(
        decode(4096, &[0x40, 0x01, b'a', 0x01, b'b', 0x20]),
        Err(Error::Size)
    );
    assert_eq!(decode(4096, &[0x20, 0x82]).unwrap().len(), 1);
    assert_eq!(
        decode(4096, &[0x20, 0x3f, 0xe1, 0x1f, 0x82]).unwrap().len(),
        1
    );
}

#[test]
fn truncated() {
    let short = Err(Error::Wire(Wire::Truncated));
    assert_eq!(decode(4096, &[0xff]), short);
    assert_eq!(decode(4096, &[0xff, 0x80]), short);
    assert_eq!(decode(4096, &[0x40]), short);
    assert_eq!(decode(4096, &[0x40, 0x0a, b'c']), short);
    assert_eq!(decode(4096, &[0x40, 0x01, b'a']), short);
    assert_eq!(decode(4096, &[0x40, 0x01, b'a', 0x05, b'b']), short);
    assert_eq!(decode(4096, &[0x44, 0x05]), short);
    assert_eq!(decode(4096, &[0x3f]), short);
}

#[test]
fn overflow() {
    let mut block = vec![0xff];
    block.extend([0xff; 10]);
    block.push(0x7f);
    assert_eq!(decode(4096, &block), Err(Error::Wire(Wire::Range)));
    let mut block = vec![0x40, 0x7f];
    block.extend([0xff; 10]);
    block.push(0x7f);
    assert_eq!(decode(4096, &block), Err(Error::Wire(Wire::Range)));
}

#[test]
fn huffman() {
    let padding = Err(Error::Wire(Wire::Padding));
    let symbol = Err(Error::Wire(Wire::Symbol));
    assert_eq!(decode(4096, &[0x40, 0x81, 0xff, 0x01, b'v']), padding);
    assert_eq!(
        decode(4096, &[0x40, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01, b'v']),
        symbol
    );
    assert_eq!(decode(4096, &[0x40, 0x01, b'n', 0x81, 0x18]), padding);
    assert_eq!(
        decode(4096, &[0x40, 0x01, b'n', 0x84, 0xff, 0xff, 0xff, 0xff]),
        symbol
    );
    assert_eq!(decode(4096, &[0x44, 0x82, 0x1f, 0xff]), padding);
}

#[test]
fn clearing() {
    let mut decoder = Decoder::new(64);
    decoder.decode(&[0x40, 0x01, b'a', 0x01, b'b']).unwrap();
    assert_eq!(decoder.size(), 34);
    let mut block = vec![0x40, 20];
    block.extend([b'x'; 20]);
    block.push(20);
    block.extend([b'y'; 20]);
    assert_eq!(decoder.decode(&block).unwrap().len(), 1);
    assert_eq!(decoder.size(), 0);
    assert!(decoder.dynamic().is_empty());
}

#[test]
fn eviction() {
    let mut decoder = Decoder::new(70);
    for name in [b'a', b'b', b'c'] {
        decoder.decode(&[0x40, 0x01, name, 0x01, b'v']).unwrap();
    }
    let kept: Vec<Vec<u8>> = decoder
        .dynamic()
        .into_iter()
        .map(|header| header.name)
        .collect();
    assert_eq!(kept, [b"c".to_vec(), b"b".to_vec()]);
    assert_eq!(decoder.size(), 68);
    assert_eq!(
        decoder.decode(&[0xbe, 0xbf]).unwrap(),
        [Header::new(b"c", b"v"), Header::new(b"b", b"v")]
    );
    assert_eq!(decoder.decode(&[0xc0]), Err(Error::Index));
}

#[test]
fn resize() {
    let mut decoder = Decoder::new(4096);
    decoder.decode(&[0x40, 0x01, b'a', 0x01, b'b']).unwrap();
    decoder.resize(0);
    assert_eq!(decoder.size(), 0);
    assert_eq!(decoder.decode(&[0xbe]), Err(Error::Index));
    assert_eq!(decoder.decode(&[0x3f, 0x01]), Err(Error::Size));
}

#[test]
fn updates() {
    let mut encoder = Encoder::new(4096, false);
    encoder.resize(100);
    assert_eq!(
        encoder.encode(&[Header::new(b":method", b"GET")]),
        [0x3f, 0x45, 0x82]
    );
    assert_eq!(encoder.encode(&[Header::new(b":method", b"GET")]), [0x82]);
    encoder.resize(10);
    encoder.resize(200);
    assert_eq!(encoder.encode(&[]), [0x2a, 0x3f, 0xa9, 0x01]);
    encoder.resize(0);
    assert_eq!(encoder.encode(&[]), [0x20]);
}
