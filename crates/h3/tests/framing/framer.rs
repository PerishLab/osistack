use crate::support::*;
use h3::{Code, Frame, Framer, Settings};

fn sample() -> (Vec<u8>, Vec<Frame>) {
    let frames = vec![
        Frame::Settings(Settings {
            capacity: 4096,
            ..Settings::default()
        }),
        Frame::Headers(vec![0, 0, 0xd1]),
        Frame::Data(b"hello".to_vec()),
        Frame::Unknown {
            kind: 0x21,
            length: 4,
        },
        Frame::Goaway(8),
        Frame::Data(vec![9; 300]),
        Frame::Unknown {
            kind: 0x40,
            length: 70,
        },
        Frame::Max(1),
    ];
    let mut input = Vec::new();
    for frame in &frames {
        input.extend(frame.encode().unwrap());
    }
    (input, frames)
}

#[test]
fn whole() {
    let (input, frames) = sample();
    let mut framer = Framer::new(1 << 16);
    assert_eq!(framer.feed(&input).unwrap(), frames);
    assert_eq!(framer.pending(), 0);
}

#[test]
fn bytewise() {
    let (input, frames) = sample();
    let mut framer = Framer::new(1 << 16);
    let mut seen = Vec::new();
    for byte in &input {
        seen.extend(framer.feed(&[*byte]).unwrap());
    }
    assert_eq!(seen, frames);
}

#[test]
fn random() {
    let (input, frames) = sample();
    for seed in 1..=60u64 {
        let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut framer = Framer::new(1 << 16);
        let mut seen = Vec::new();
        let mut at = 0;
        while at < input.len() {
            let take = 1 + dice.roll(40) as usize;
            let end = (at + take).min(input.len());
            seen.extend(framer.feed(&input[at..end]).unwrap());
            at = end;
        }
        assert_eq!(seen, frames, "seed {seed}");
    }
}

#[test]
fn skipped() {
    let mut framer = Framer::new(64);
    let mut head = vec![0x21];
    head.extend(bytes("80 01 86 a0"));
    let mut seen = framer.feed(&head).unwrap();
    assert_eq!(
        seen,
        vec![Frame::Unknown {
            kind: 0x21,
            length: 100_000
        }]
    );
    for _ in 0..100 {
        seen.extend(framer.feed(&[5; 1000]).unwrap());
        assert!(framer.pending() < 16);
    }
    assert_eq!(seen.len(), 1);
    let next = Frame::Data(b"ok".to_vec());
    seen.extend(framer.feed(&next.encode().unwrap()).unwrap());
    assert_eq!(seen[1], next);
}

#[test]
fn heavy() {
    let mut framer = Framer::new(63);
    let head = bytes("00 40 40");
    assert_eq!(framer.feed(&head), Err(connection(Code::Load)));
    let mut fine = Framer::new(64);
    let mut input = head.clone();
    input.extend([1; 64]);
    assert_eq!(fine.feed(&input).unwrap().len(), 1);
}

#[test]
fn reserved() {
    for kind in [0x02u8, 0x06, 0x08, 0x09] {
        let mut framer = Framer::new(64);
        let fault = framer.feed(&[kind, 0]).unwrap_err();
        assert_eq!(fault, connection(Code::Unexpected));
    }
}

#[test]
fn malformed() {
    let mut framer = Framer::new(64);
    let fault = framer.feed(&bytes("07 02 01 01")).unwrap_err();
    assert_eq!(fault, connection(Code::Frame));
}
