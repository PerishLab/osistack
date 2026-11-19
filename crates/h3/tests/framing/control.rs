use crate::support::*;
use h3::{Code, Control, Fault, Frame, Notice, Settings};

fn stream(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .flat_map(|frame| frame.encode().unwrap())
        .collect()
}

fn first() -> Frame {
    Frame::Settings(Settings {
        capacity: 4096,
        ..Settings::default()
    })
}

fn run(frames: &[Frame]) -> Result<Vec<Notice>, Fault> {
    Control::new(1 << 16).feed(&stream(frames))
}

#[test]
fn opened() {
    let settings = Settings {
        capacity: 4096,
        size: Some(100),
        blocked: 16,
    };
    let expected = bytes("00 04 08 01 50 00 06 40 64 07 10");
    assert_eq!(Control::open(&settings).unwrap(), expected);
    assert_eq!(
        Control::open(&Settings::default()).unwrap(),
        bytes("00 04 00")
    );
    let over = Settings {
        capacity: 1 << 62,
        ..Settings::default()
    };
    assert_eq!(Control::open(&over), Err(connection(Code::Internal)));
}

#[test]
fn accepted() {
    let frames = [
        first(),
        Frame::Goaway(8),
        Frame::Unknown {
            kind: 0x21,
            length: 3,
        },
        Frame::Goaway(4),
        Frame::Goaway(4),
        Frame::Goaway(0),
    ];
    let notices = run(&frames).unwrap();
    let settings = Settings {
        capacity: 4096,
        ..Settings::default()
    };
    let expected = vec![
        Notice::Settings(settings.clone()),
        Notice::Goaway(8),
        Notice::Goaway(4),
        Notice::Goaway(4),
        Notice::Goaway(0),
    ];
    assert_eq!(notices, expected);
    let mut control = Control::new(1 << 16);
    assert!(control.settings().is_none());
    control.feed(&stream(&frames)).unwrap();
    assert_eq!(control.settings(), Some(&settings));
}

#[test]
fn bytewise() {
    let frames = [first(), Frame::Goaway(8), Frame::Goaway(4)];
    let mut control = Control::new(1 << 16);
    let mut seen = Vec::new();
    for byte in stream(&frames) {
        seen.extend(control.feed(&[byte]).unwrap());
    }
    assert_eq!(seen, run(&frames).unwrap());
}

#[test]
fn missing() {
    let others = [
        Frame::Headers(vec![0]),
        Frame::Data(vec![0]),
        Frame::Goaway(0),
        Frame::Cancel(0),
        Frame::Max(0),
        Frame::Unknown {
            kind: 0x21,
            length: 0,
        },
    ];
    for frame in others {
        let fault = run(std::slice::from_ref(&frame)).unwrap_err();
        assert_eq!(fault, connection(Code::Missing), "{frame:?}");
    }
}

#[test]
fn unexpected() {
    let others = [
        first(),
        Frame::Data(vec![0]),
        Frame::Headers(vec![0]),
        Frame::Promise {
            push: 0,
            block: Vec::new(),
        },
        Frame::Max(0),
    ];
    for frame in others {
        let fault = run(&[first(), frame.clone()]).unwrap_err();
        assert_eq!(fault, connection(Code::Unexpected), "{frame:?}");
    }
    let reserved = [first().encode().unwrap(), vec![0x09, 0]].concat();
    let fault = Control::new(64).feed(&reserved).unwrap_err();
    assert_eq!(fault, connection(Code::Unexpected));
}

#[test]
fn pushes() {
    for push in [0, 1, 100] {
        let fault = run(&[first(), Frame::Cancel(push)]).unwrap_err();
        assert_eq!(fault, connection(Code::Id), "{push}");
    }
}

#[test]
fn goaway() {
    for id in [1, 2, 3, 5, 6, 7, 9] {
        let fault = run(&[first(), Frame::Goaway(id)]).unwrap_err();
        assert_eq!(fault, connection(Code::Id), "{id}");
    }
    let raised = run(&[first(), Frame::Goaway(8), Frame::Goaway(12)]);
    assert_eq!(raised, Err(connection(Code::Id)));
}

#[test]
fn malformed() {
    let mut input = first().encode().unwrap();
    input.extend(bytes("04 04 01 01 01 02"));
    let fault = Control::new(64).feed(&input).unwrap_err();
    assert_eq!(fault, connection(Code::Setting));
    let heavy = [first().encode().unwrap(), bytes("00 40 41")].concat();
    let fault = Control::new(64).feed(&heavy).unwrap_err();
    assert_eq!(fault, connection(Code::Load));
}

#[test]
fn closed() {
    let control = Control::new(64);
    assert_eq!(control.end(), connection(Code::Critical));
}
