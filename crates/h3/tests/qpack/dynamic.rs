use h3::{Dynamic, Error, Field};

fn field(name: &str, value: &str) -> Field {
    Field::new(name.as_bytes(), value.as_bytes())
}

#[test]
fn accounting() {
    let mut table = Dynamic::new(200);
    assert_eq!(
        (table.capacity(), table.size(), table.inserted()),
        (0, 0, 0)
    );
    table.resize(100).unwrap();
    assert_eq!(table.insert(field("ab", "cde")).unwrap(), 0);
    assert_eq!(table.size(), 37);
    assert_eq!(table.insert(field("", "")).unwrap(), 1);
    assert_eq!(table.size(), 69);
    assert_eq!(table.dropped(), 0);
}

#[test]
fn eviction() {
    let mut table = Dynamic::new(100);
    table.resize(100).unwrap();
    for name in ["a", "b", "c"] {
        table.insert(field(name, "")).unwrap();
    }
    assert_eq!(table.size(), 99);
    assert_eq!(table.insert(field("d", "")).unwrap(), 3);
    assert_eq!(table.dropped(), 1);
    assert_eq!(table.size(), 99);
    assert!(table.get(0).is_none());
    assert_eq!(table.get(1), Some(&field("b", "")));
    assert_eq!(table.get(3), Some(&field("d", "")));
    assert!(table.get(4).is_none());
}

#[test]
fn shrinking() {
    let mut table = Dynamic::new(100);
    table.resize(100).unwrap();
    for name in ["a", "b", "c"] {
        table.insert(field(name, "")).unwrap();
    }
    table.resize(70).unwrap();
    assert_eq!((table.dropped(), table.size()), (1, 66));
    table.resize(0).unwrap();
    assert_eq!((table.dropped(), table.size(), table.inserted()), (3, 0, 3));
    assert!(table.entries().is_empty());
}

#[test]
fn relative() {
    let mut table = Dynamic::new(200);
    table.resize(200).unwrap();
    assert_eq!(table.relative(0), None);
    for name in ["a", "b", "c"] {
        table.insert(field(name, "")).unwrap();
    }
    assert_eq!(table.relative(0), Some(2));
    assert_eq!(table.relative(2), Some(0));
    assert_eq!(table.relative(3), None);
}

#[test]
fn limits() {
    let mut table = Dynamic::new(100);
    assert_eq!(table.resize(101), Err(Error::Capacity));
    assert_eq!(table.insert(field("a", "")), Err(Error::Oversize));
    table.resize(40).unwrap();
    assert_eq!(table.insert(field("abcdefgh", "i")), Err(Error::Oversize));
    assert_eq!(table.insert(field("abcdefg", "")).unwrap(), 0);
    assert_eq!(table.insert(field("abcdefghi", "")), Err(Error::Oversize));
    assert_eq!(table.inserted(), 1);
}
