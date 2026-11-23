use h3::{Decoder, Error, Field};
use std::env;
use std::fs;
use std::path::Path;
use wire::Error as Wire;

fn decode(block: &[u8]) -> Result<Vec<Field>, Error> {
    Decoder::new(0).decode(block)
}

#[test]
fn beyond() {
    assert_eq!(decode(&[0, 0, 0xff, 0x24]), Err(Error::Index));
    assert_eq!(decode(&[0, 0, 0x5f, 0x54, 0x00]), Err(Error::Index));
    assert_eq!(decode(&[0, 0, 0x7f, 0x54, 0x00]), Err(Error::Index));
    assert_eq!(decode(&[0, 0, 0xff, 0x23]).unwrap().len(), 1);
    assert_eq!(decode(&[0, 0, 0x5f, 0x53, 0x00]).unwrap().len(), 1);
}

#[test]
fn dynamic() {
    assert_eq!(decode(&[0, 0, 0x80]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0xbf, 0x00]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0x40, 0x00]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0x60, 0x00]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0x10]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0x1f, 0x00]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0x00, 0x00]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0x0f, 0x00]), Err(Error::Dynamic));
    assert_eq!(decode(&[0, 0, 0xc1, 0x80]), Err(Error::Dynamic));
}

#[test]
fn needed() {
    let decoder = Decoder::new(220);
    assert_eq!(
        decoder.decode(&[0x03, 0x81, 0x10, 0x11]),
        Err(Error::Dynamic)
    );
    assert_eq!(decoder.decode(&[0x05, 0x00, 0x80]), Err(Error::Dynamic));
    assert_eq!(decoder.decode(&[0x00, 0x00, 0xc1]).unwrap().len(), 1);
}

#[test]
fn prefix() {
    assert_eq!(decode(&[0x01, 0x00]), Err(Error::Count));
    assert_eq!(Decoder::new(96).decode(&[0x01, 0x00]), Err(Error::Count));
    assert_eq!(Decoder::new(96).decode(&[0x07, 0x00]), Err(Error::Count));
    assert_eq!(Decoder::new(220).decode(&[0x03, 0x82]), Err(Error::Base));
    assert_eq!(decode(&[0x00, 0x80]), Err(Error::Base));
}

#[test]
fn short() {
    assert_eq!(decode(&[]), Err(Error::Wire(Wire::Truncated)));
    assert_eq!(decode(&[0x00]), Err(Error::Wire(Wire::Truncated)));
    assert_eq!(decode(&[0, 0, 0xff]), Err(Error::Wire(Wire::Truncated)));
    assert_eq!(decode(&[0, 0, 0x51]), Err(Error::Wire(Wire::Truncated)));
    assert_eq!(
        decode(&[0, 0, 0x51, 0x02, b'a']),
        Err(Error::Wire(Wire::Truncated))
    );
    assert_eq!(
        decode(&[0, 0, 0x27, 0x03, b'a']),
        Err(Error::Wire(Wire::Truncated))
    );
    assert_eq!(decode(&[0, 0, 0x20]), Err(Error::Wire(Wire::Truncated)));
    assert_eq!(
        decode(&[0, 0, 0x21, 0x00]),
        Err(Error::Wire(Wire::Truncated))
    );
}

#[test]
fn overflow() {
    let mut block = vec![0, 0, 0x5f];
    block.extend([0xff; 10]);
    block.push(0x01);
    assert_eq!(decode(&block), Err(Error::Wire(Wire::Range)));
    let mut long = vec![0, 0, 0x51, 0xff];
    long.extend([0xff; 11]);
    long.push(0x01);
    assert_eq!(decode(&long), Err(Error::Wire(Wire::Range)));
}

#[test]
fn padding() {
    assert_eq!(
        decode(&[0, 0, 0x51, 0x81, 0x00]),
        Err(Error::Wire(Wire::Padding))
    );
    assert_eq!(
        decode(&[0, 0, 0x51, 0x81, 0xff]),
        Err(Error::Wire(Wire::Padding))
    );
    assert_eq!(
        decode(&[0, 0, 0x29, 0x00, 0x00]),
        Err(Error::Wire(Wire::Padding))
    );
}

#[test]
fn symbol() {
    let eos = [0xff, 0xff, 0xff, 0xff];
    let mut block = vec![0, 0, 0x51, 0x84];
    block.extend(eos);
    assert_eq!(decode(&block), Err(Error::Wire(Wire::Symbol)));
}

#[test]
#[ignore = "corpus"]
fn walking() {
    let Ok(root) = env::var("OSISTACK_CORPUS") else {
        return;
    };
    if root.is_empty() {
        return;
    }
    let path = Path::new(&root);
    if !path.is_dir() {
        return;
    }
    visit(path);
}

fn visit(path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path);
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let parsed = std::panic::catch_unwind(|| {
            let _ = Decoder::new(4096).decode(&bytes);
        });
        assert!(parsed.is_ok(), "{}", path.display());
    }
}
