use h3::{Error, Section};
use wire::{Reader, Writer};

fn read(block: &[u8], capacity: usize, inserted: u64) -> Result<Section, Error> {
    Section::read(&mut Reader::new(block), capacity, inserted)
}

fn write(section: Section, capacity: usize) -> Vec<u8> {
    let mut writer = Writer::new();
    section.write(&mut writer, capacity).unwrap();
    writer.finish()
}

#[test]
fn wrapped() {
    let section = read(&[0x04, 0x82], 100, 10).unwrap();
    assert_eq!(
        section,
        Section {
            required: 9,
            base: 6
        }
    );
    assert_eq!(write(section, 100), vec![0x04, 0x82]);
}

#[test]
fn example() {
    let section = read(&[0x03, 0x81], 220, 2).unwrap();
    assert_eq!(
        section,
        Section {
            required: 2,
            base: 0
        }
    );
    assert_eq!(write(section, 220), vec![0x03, 0x81]);
}

#[test]
fn caught() {
    let section = read(&[0x05, 0x00], 220, 4).unwrap();
    assert_eq!(
        section,
        Section {
            required: 4,
            base: 4
        }
    );
    assert_eq!(write(section, 220), vec![0x05, 0x00]);
}

#[test]
fn empty() {
    assert_eq!(
        read(&[0x00, 0x00], 0, 0),
        Ok(Section {
            required: 0,
            base: 0
        })
    );
    assert_eq!(
        write(
            Section {
                required: 0,
                base: 0
            },
            0
        ),
        vec![0, 0]
    );
}

#[test]
fn ahead() {
    assert_eq!(
        read(&[0x00, 0x05], 0, 0),
        Ok(Section {
            required: 0,
            base: 5
        })
    );
    assert_eq!(read(&[0x03, 0x00], 220, 14).unwrap().required, 14);
    assert_eq!(read(&[0x03, 0x00], 220, 2).unwrap().required, 2);
}

fn sweep(capacity: usize, inserted: u64) {
    let entries = (capacity / 32) as u64;
    let high = inserted + entries;
    let low = (high + 1).saturating_sub(entries * 2).max(1);
    for required in low..=high {
        for base in [0, required.saturating_sub(1), required, required + 3] {
            let section = Section { required, base };
            let block = write(section, capacity);
            assert_eq!(read(&block, capacity, inserted), Ok(section));
        }
    }
}

#[test]
fn window() {
    for capacity in [32usize, 64, 100, 220, 4096] {
        for inserted in 0..400u64 {
            sweep(capacity, inserted);
        }
    }
}

#[test]
fn bounds() {
    assert_eq!(read(&[0x01, 0x00], 0, 0), Err(Error::Count));
    assert_eq!(read(&[0x07, 0x00], 96, 0), Err(Error::Count));
    assert_eq!(read(&[0x01, 0x00], 96, 0), Err(Error::Count));
    assert_eq!(read(&[0x05, 0x00], 96, 0), Err(Error::Count));
    assert_eq!(
        read(&[0x04, 0x00], 96, 0),
        Ok(Section {
            required: 3,
            base: 3
        })
    );
    assert_eq!(read(&[0x06, 0x00], 96, 0), Err(Error::Count));
    let mut writer = Writer::new();
    let section = Section {
        required: 1,
        base: 1,
    };
    assert_eq!(section.write(&mut writer, 0), Err(Error::Count));
}

#[test]
fn negative() {
    assert_eq!(read(&[0x03, 0x82], 220, 2), Err(Error::Base));
    assert_eq!(
        read(&[0x03, 0x81], 220, 2),
        Ok(Section {
            required: 2,
            base: 0
        })
    );
    assert_eq!(read(&[0x00, 0x80], 0, 0), Err(Error::Base));
}

#[test]
fn short() {
    assert_eq!(read(&[], 220, 0), Err(Error::Wire(wire::Error::Truncated)));
    assert_eq!(
        read(&[0x03], 220, 2),
        Err(Error::Wire(wire::Error::Truncated))
    );
}
