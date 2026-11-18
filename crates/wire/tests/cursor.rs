use wire::{Error, Reader, Writer};

#[test]
fn reading() {
    let mut reader = Reader::new(&[1, 2, 3, 4, 5]);
    assert_eq!(reader.byte(), Ok(1));
    assert_eq!(reader.take(3), Ok(&[2, 3, 4][..]));
    assert_eq!(reader.at(), 4);
    assert_eq!(reader.left(), 1);
    assert_eq!(reader.byte(), Ok(5));
    assert_eq!(reader.left(), 0);
}

#[test]
fn bounds() {
    let mut reader = Reader::new(&[1, 2]);
    assert_eq!(reader.take(3), Err(Error::Truncated));
    assert_eq!(reader.at(), 0);
    assert_eq!(reader.take(2), Ok(&[1, 2][..]));
    assert_eq!(reader.byte(), Err(Error::Truncated));
    assert_eq!(reader.take(usize::MAX), Err(Error::Truncated));
    assert_eq!(reader.at(), 2);
}

#[test]
fn empty() {
    let mut reader = Reader::new(&[]);
    assert_eq!(reader.left(), 0);
    assert_eq!(reader.byte(), Err(Error::Truncated));
    assert_eq!(reader.take(0), Ok(&[][..]));
}

#[test]
fn writing() {
    let mut writer = Writer::new();
    writer.byte(9);
    writer.put(&[8, 7]);
    assert_eq!(writer.written(), &[9, 8, 7]);
    assert_eq!(writer.finish(), vec![9, 8, 7]);
}
