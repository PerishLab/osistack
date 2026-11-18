use wire::{Error, Huffman};

fn everything() -> Vec<u8> {
    (0..=255).collect()
}

#[test]
fn single() {
    let huffman = Huffman::new();
    for byte in everything() {
        let coded = huffman.encode(&[byte]);
        assert_eq!(coded.len(), huffman.size(&[byte]));
        assert_eq!(huffman.decode(&coded), Ok(vec![byte]), "{byte}");
    }
}

#[test]
fn sequence() {
    let huffman = Huffman::new();
    let mut forward = everything();
    assert_eq!(
        huffman.decode(&huffman.encode(&forward)),
        Ok(forward.clone())
    );
    forward.reverse();
    assert_eq!(huffman.decode(&huffman.encode(&forward)), Ok(forward));
}

#[test]
fn empty() {
    let huffman = Huffman::new();
    assert_eq!(huffman.encode(&[]), Vec::<u8>::new());
    assert_eq!(huffman.size(&[]), 0);
    assert_eq!(huffman.decode(&[]), Ok(Vec::new()));
}

#[test]
fn lengths() {
    let huffman = Huffman::new();
    assert_eq!(huffman.length(0), Some(13));
    assert_eq!(huffman.length(b'0' as u16), Some(5));
    assert_eq!(huffman.length(b' ' as u16), Some(6));
    assert_eq!(huffman.length(b'!' as u16), Some(10));
    assert_eq!(huffman.length(255), Some(26));
    assert_eq!(huffman.length(256), Some(30));
    assert_eq!(huffman.length(257), None);
}

#[test]
fn symbol() {
    let huffman = Huffman::new();
    assert_eq!(
        huffman.decode(&[0xff, 0xff, 0xff, 0xff]),
        Err(Error::Symbol)
    );
    assert_eq!(
        huffman.decode(&[0x1f, 0xff, 0xff, 0xff, 0xfc]),
        Err(Error::Symbol)
    );
}

#[test]
fn excess() {
    let huffman = Huffman::new();
    assert_eq!(huffman.decode(&[0xff]), Err(Error::Padding));
    assert_eq!(huffman.decode(&[0x1f, 0xff]), Err(Error::Padding));
}

#[test]
fn zeros() {
    let huffman = Huffman::new();
    assert_eq!(huffman.decode(&[0x18]), Err(Error::Padding));
    assert_eq!(huffman.decode(&[0x00]), Err(Error::Padding));
}

#[test]
fn partial() {
    let huffman = Huffman::new();
    assert_eq!(huffman.decode(&[0x1f]), Ok(vec![b'a']));
    assert_eq!(huffman.decode(&[0xff, 0xfe]), Err(Error::Padding));
}
