use h3::{Decoder, Encoder, Field};

fn decode(block: &[u8]) -> Vec<Field> {
    Decoder::new(0).decode(block).unwrap()
}

#[test]
fn literal() {
    let block = [
        0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c,
    ];
    let field = Field::new(b":path", b"/index.html");
    assert_eq!(decode(&block), vec![field.clone()]);
    assert_eq!(Encoder::new(false).encode(&[field]), block);
}

#[test]
fn indexed() {
    assert_eq!(
        decode(&[0x00, 0x00, 0xc1]),
        vec![Field::new(b":path", b"/")]
    );
    let fields = vec![
        Field::new(b":method", b"GET"),
        Field::new(b":scheme", b"https"),
    ];
    assert_eq!(decode(&[0x00, 0x00, 0xd1, 0xd7]), fields);
    assert_eq!(Encoder::new(true).encode(&fields), [0x00, 0x00, 0xd1, 0xd7]);
}

#[test]
fn hidden() {
    let field = Field::secret(b":path", b"/");
    let block = [0x00, 0x00, 0x71, 0x01, 0x2f];
    assert_eq!(decode(&block), vec![field.clone()]);
    assert_eq!(Encoder::new(false).encode(&[field]), block);
}

#[test]
fn huffman() {
    let block = [
        0x00, 0x00, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4,
        0xff,
    ];
    let field = Field::new(b":authority", b"www.example.com");
    assert_eq!(decode(&block), vec![field.clone()]);
    assert_eq!(Encoder::new(true).encode(&[field]), block);
}

#[test]
fn spelled() {
    let block = [
        0x00, 0x00, 0x27, 0x03, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0c,
        b'c', b'u', b's', b't', b'o', b'm', b'-', b'v', b'a', b'l', b'u', b'e',
    ];
    let field = Field::new(b"custom-key", b"custom-value");
    assert_eq!(decode(&block), vec![field.clone()]);
    assert_eq!(Encoder::new(false).encode(&[field]), block);
}

#[test]
fn coded() {
    let block = [
        0x00, 0x00, 0x2f, 0x01, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8,
        0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
    ];
    let field = Field::new(b"custom-key", b"custom-value");
    assert_eq!(decode(&block), vec![field.clone()]);
    assert_eq!(Encoder::new(true).encode(&[field]), block);
}

#[test]
fn secret() {
    let block = [
        0x00, 0x00, 0x37, 0x03, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x01,
        b'v',
    ];
    let field = Field::secret(b"custom-key", b"v");
    assert_eq!(decode(&block), vec![field.clone()]);
    assert_eq!(Encoder::new(false).encode(&[field]), block);
}

#[test]
fn several() {
    let block = [
        0x00, 0x00, 0xd1, 0xc1, 0x50, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o',
        b'r', b'g',
    ];
    let fields = vec![
        Field::new(b":method", b"GET"),
        Field::new(b":path", b"/"),
        Field::new(b":authority", b"example.org"),
    ];
    assert_eq!(decode(&block), fields);
    assert_eq!(Encoder::new(false).encode(&fields), block);
}

#[test]
fn nothing() {
    assert_eq!(decode(&[0x00, 0x00]), Vec::new());
    assert_eq!(Encoder::new(false).encode(&[]), [0x00, 0x00]);
}
