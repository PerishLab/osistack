use crate::support::*;
use h3::{Code, Frame, Settings};

const LIMIT: usize = 1 << 20;

fn vectors() -> Vec<(&'static str, Frame)> {
    let settings = |capacity, size, blocked| {
        Frame::Settings(Settings {
            capacity,
            size,
            blocked,
        })
    };
    vec![
        ("00 02 68 69", Frame::Data(b"hi".to_vec())),
        ("00 00", Frame::Data(Vec::new())),
        ("01 02 00 00", Frame::Headers(vec![0, 0])),
        ("03 01 05", Frame::Cancel(5)),
        ("04 00", settings(0, None, 0)),
        ("04 03 01 50 00", settings(4096, None, 0)),
        ("04 03 06 40 64", settings(0, Some(100), 0)),
        ("04 02 07 10", settings(0, None, 16)),
        (
            "04 08 01 50 00 06 40 64 07 10",
            settings(4096, Some(100), 16),
        ),
        (
            "05 02 03 01",
            Frame::Promise {
                push: 3,
                block: vec![1],
            },
        ),
        ("07 01 08", Frame::Goaway(8)),
        ("07 02 40 40", Frame::Goaway(64)),
        ("0d 01 02", Frame::Max(2)),
        (
            "21 03 aa bb cc",
            Frame::Unknown {
                kind: 0x21,
                length: 3,
            },
        ),
        (
            "40 40 00",
            Frame::Unknown {
                kind: 0x40,
                length: 0,
            },
        ),
        (
            "40 5f 01 ff",
            Frame::Unknown {
                kind: 0x5f,
                length: 1,
            },
        ),
    ]
}

#[test]
fn known() {
    for (hex, frame) in vectors() {
        let input = bytes(hex);
        let (decoded, used) = Frame::decode(&input, LIMIT).unwrap().unwrap();
        assert_eq!(decoded, frame, "{hex}");
        assert_eq!(used, input.len(), "{hex}");
    }
}

#[test]
fn encoded() {
    for (hex, frame) in vectors() {
        let output = frame.encode().unwrap();
        let (again, used) = Frame::decode(&output, LIMIT).unwrap().unwrap();
        assert_eq!(again, frame, "{hex}");
        assert_eq!(used, output.len());
        if !matches!(frame, Frame::Unknown { .. }) {
            assert_eq!(output, bytes(hex), "{hex}");
        }
    }
    let grease = Frame::Unknown {
        kind: 0x21,
        length: 3,
    };
    assert_eq!(grease.encode().unwrap(), bytes("21 03 00 00 00"));
}

#[test]
fn lengths() {
    let heads = [
        (63, "00 3f"),
        (64, "00 40 40"),
        (16383, "00 7f ff"),
        (16384, "00 80 00 40 00"),
    ];
    for (size, head) in heads {
        let frame = Frame::Data(vec![7; size]);
        let output = frame.encode().unwrap();
        let prefix = bytes(head);
        assert_eq!(&output[..prefix.len()], &prefix[..], "{size}");
        assert_eq!(output.len(), prefix.len() + size);
        let (decoded, used) = Frame::decode(&output, LIMIT).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(used, output.len());
    }
}

#[test]
fn greased() {
    for number in [0u64, 1, 2, 100, 1000] {
        let kind = 0x1f * number + 0x21;
        let frame = Frame::Unknown { kind, length: 2 };
        let output = frame.encode().unwrap();
        let (decoded, _) = Frame::decode(&output, LIMIT).unwrap().unwrap();
        assert_eq!(decoded, frame, "{kind:#x}");
    }
}

#[test]
fn reserved() {
    for kind in [0x02, 0x06, 0x08, 0x09] {
        let input = [kind, 0];
        let fault = Frame::decode(&input, LIMIT).unwrap_err();
        assert_eq!(fault, connection(Code::Unexpected), "{kind}");
        let local = Frame::Unknown {
            kind: u64::from(kind),
            length: 0,
        };
        assert_eq!(local.encode(), Err(connection(Code::Internal)));
    }
}

#[test]
fn malformed() {
    let cases = [
        "03 02 05 06",
        "03 00",
        "03 01 40",
        "07 02 01 01",
        "07 00",
        "0d 03 40 02 00",
        "0d 00",
        "04 01 01",
        "04 02 01 40",
        "05 00",
        "05 01 40",
    ];
    for hex in cases {
        let fault = Frame::decode(&bytes(hex), LIMIT).unwrap_err();
        assert_eq!(fault, connection(Code::Frame), "{hex}");
    }
}

#[test]
fn limited() {
    let mut input = bytes("00 05");
    assert_eq!(Frame::decode(&input, 4), Err(connection(Code::Load)));
    input.extend([1, 2, 3, 4, 5]);
    assert_eq!(Frame::decode(&input, 4), Err(connection(Code::Load)));
    assert!(Frame::decode(&input, 5).unwrap().is_some());
    let grease = bytes("21 05 01 02 03 04 05");
    assert_eq!(Frame::decode(&grease, 4), Err(connection(Code::Load)));
}

#[test]
fn partial() {
    for (hex, _) in vectors() {
        let input = bytes(hex);
        for cut in 0..input.len() {
            assert_eq!(Frame::decode(&input[..cut], LIMIT), Ok(None), "{hex} {cut}");
        }
        let mut longer = input.clone();
        longer.extend([0xee, 0xee]);
        let (_, used) = Frame::decode(&longer, LIMIT).unwrap().unwrap();
        assert_eq!(used, input.len(), "{hex}");
    }
}

#[test]
fn range() {
    assert_eq!(
        Frame::Cancel(1 << 62).encode(),
        Err(connection(Code::Internal))
    );
    let top = Frame::Cancel((1 << 62) - 1);
    let output = top.encode().unwrap();
    assert_eq!(output, bytes("03 08 ff ff ff ff ff ff ff ff"));
    assert_eq!(Frame::decode(&output, LIMIT).unwrap().unwrap().0, top);
}
