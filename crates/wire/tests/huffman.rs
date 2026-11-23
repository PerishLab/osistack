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

fn step(seed: u64) -> u64 {
    seed.wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

fn fills(seed: &mut u64) -> Vec<u8> {
    *seed = step(*seed);
    let length = 1 + ((*seed >> 33) as usize % 48);
    let mut data = Vec::with_capacity(length);
    for _ in 0..length {
        *seed = step(*seed);
        data.push((*seed >> 33) as u8);
    }
    data
}

fn prefix(huffman: &Huffman, data: &[u8], coded: &[u8], cut: usize) {
    let got = huffman.decode(&coded[..cut]);
    if let Ok(part) = &got {
        assert!(data.starts_with(part), "{cut}");
        assert_ne!(part, data);
    }
    if let Err(err) = &got {
        assert!(
            matches!(err, Error::Padding | Error::Symbol),
            "{err:?} {cut}"
        );
    }
}

#[test]
fn trips() {
    let huffman = Huffman::new();
    let mut seed = 11u64;
    for _ in 0..200 {
        let data = fills(&mut seed);
        let coded = huffman.encode(&data);
        assert_eq!(coded.len(), huffman.size(&data));
        assert_eq!(huffman.decode(&coded), Ok(data.clone()));
        for cut in 0..coded.len() {
            prefix(&huffman, &data, &coded, cut);
        }
    }
}

#[test]
fn cuts() {
    let huffman = Huffman::new();
    for byte in everything() {
        let coded = huffman.encode(&[byte]);
        for cut in 0..coded.len() {
            let got = huffman.decode(&coded[..cut]);
            assert_ne!(got, Ok(vec![byte]), "{byte} {cut}");
            let _ = got;
        }
    }
}
