use crate::support::*;
use h3::{Code, Fault, Frame, Settings};

fn read(hex: &str) -> Result<Settings, Fault> {
    let payload = bytes(hex);
    let mut input = vec![0x04, payload.len() as u8];
    input.extend(payload);
    match Frame::decode(&input, 1 << 16)? {
        Some((Frame::Settings(settings), _)) => Ok(settings),
        other => panic!("{other:?}"),
    }
}

#[test]
fn decoded() {
    let all = read("01 50 00 06 40 64 07 10").unwrap();
    assert_eq!(all.capacity, 4096);
    assert_eq!(all.size, Some(100));
    assert_eq!(all.blocked, 16);
    assert_eq!(read("").unwrap(), Settings::default());
    assert_eq!(read("07 10 01 50 00").unwrap().capacity, 4096);
}

#[test]
fn defaults() {
    let base = Settings::default();
    assert_eq!(base.capacity, 0);
    assert_eq!(base.size, None);
    assert_eq!(base.blocked, 0);
    assert_eq!(base.write().unwrap(), Vec::<u8>::new());
    let zero = Settings {
        size: Some(0),
        ..Settings::default()
    };
    assert_eq!(zero.write().unwrap(), bytes("06 00"));
}

#[test]
fn ignored() {
    assert_eq!(read("21 05").unwrap(), Settings::default());
    assert_eq!(read("40 40 08 08 01").unwrap(), Settings::default());
    assert_eq!(read("33 01 01 50 00").unwrap().capacity, 4096);
}

#[test]
fn duplicate() {
    let fault = connection(Code::Setting);
    assert_eq!(read("01 01 01 02"), Err(fault));
    assert_eq!(read("06 01 07 01 06 02"), Err(fault));
    assert_eq!(read("21 01 21 02"), Err(fault));
}

#[test]
fn reserved() {
    for id in ["00", "02", "03", "04", "05"] {
        let hex = format!("{id} 00");
        assert_eq!(read(&hex), Err(connection(Code::Setting)), "{id}");
    }
}

#[test]
fn largest() {
    let top = (1u64 << 62) - 1;
    let settings = Settings {
        capacity: top,
        size: Some(top),
        blocked: top,
    };
    let payload = settings.write().unwrap();
    assert_eq!(payload.len(), 3 * 9);
    assert_eq!(&payload[..9], &bytes("01 ff ff ff ff ff ff ff ff")[..]);
    let (_, rest) = payload.split_at(0);
    let mut input = vec![0x04, rest.len() as u8];
    input.extend(rest);
    let (frame, _) = Frame::decode(&input, 1 << 16).unwrap().unwrap();
    assert_eq!(frame, Frame::Settings(settings));
    let over = Settings {
        blocked: 1 << 62,
        ..Settings::default()
    };
    assert_eq!(over.write(), Err(connection(Code::Internal)));
}
