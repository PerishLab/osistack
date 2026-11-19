use h2::{Decoder, Encoder, Header};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn indexing() {
    let hex = "400a637573746f6d2d6b65790d637573746f6d2d686561646572";
    let header = Header::new(b"custom-key", b"custom-header");
    let mut decoder = Decoder::new(4096);
    assert_eq!(decoder.decode(&bytes(hex)).unwrap(), vec![header.clone()]);
    assert_eq!(decoder.size(), 55);
    assert_eq!(decoder.dynamic(), vec![header.clone()]);
    let mut encoder = Encoder::new(4096, false);
    assert_eq!(encoder.encode(&[header]), bytes(hex));
}

#[test]
fn unindexed() {
    let hex = "040c2f73616d706c652f70617468";
    let header = Header::new(b":path", b"/sample/path");
    let mut decoder = Decoder::new(4096);
    assert_eq!(decoder.decode(&bytes(hex)).unwrap(), [header]);
    assert_eq!(decoder.size(), 0);
    assert!(decoder.dynamic().is_empty());
}

#[test]
fn never() {
    let hex = "100870617373776f7264067365637265 74".replace(' ', "");
    let header = Header::secret(b"password", b"secret");
    let mut decoder = Decoder::new(4096);
    assert_eq!(decoder.decode(&bytes(&hex)).unwrap(), vec![header.clone()]);
    assert_eq!(decoder.size(), 0);
    let mut encoder = Encoder::new(4096, false);
    assert_eq!(encoder.encode(&[header]), bytes(&hex));
    assert_eq!(encoder.size(), 0);
}

#[test]
fn indexed() {
    let header = Header::new(b":method", b"GET");
    let mut decoder = Decoder::new(4096);
    assert_eq!(decoder.decode(&[0x82]).unwrap(), vec![header.clone()]);
    assert_eq!(decoder.size(), 0);
    let mut encoder = Encoder::new(4096, false);
    assert_eq!(encoder.encode(&[header]), [0x82]);
}

#[test]
fn statics() {
    let mut decoder = Decoder::new(0);
    let first = decoder.decode(&[0x81]).unwrap();
    assert_eq!(first, [Header::new(b":authority", b"")]);
    let last = decoder.decode(&[0xbd]).unwrap();
    assert_eq!(last, [Header::new(b"www-authenticate", b"")]);
    let gzip = decoder.decode(&[0x90]).unwrap();
    assert_eq!(gzip, [Header::new(b"accept-encoding", b"gzip, deflate")]);
}
