use crate::support::*;
use h3::{Code, Event, Fault, Frame, Request, Settings};

fn run(frames: &[Frame]) -> Result<Vec<Event>, Fault> {
    Request::new(1 << 16).feed(&wire(frames))
}

fn head(bytes: &[u8]) -> Frame {
    Frame::Headers(bytes.to_vec())
}

fn data(bytes: &[u8]) -> Frame {
    Frame::Data(bytes.to_vec())
}

fn grease(kind: u64, length: u64) -> Frame {
    Frame::Unknown { kind, length }
}

fn lone(frame: Frame) -> Vec<Frame> {
    vec![frame]
}

#[test]
fn message() {
    let frames = [head(b"h"), data(b"he"), data(b"llo"), head(b"t")];
    let events = run(&frames).unwrap();
    let expected = vec![
        Event::Headers(b"h".to_vec()),
        Event::Data(b"he".to_vec()),
        Event::Data(b"llo".to_vec()),
        Event::Trailers(b"t".to_vec()),
    ];
    assert_eq!(events, expected);
    assert_eq!(Request::new(64).end(), Ok(Event::End));
}

#[test]
fn chunks() {
    let mut request = Request::new(64);
    request.feed(&wire(&[head(b"h")])).unwrap();
    let all = data(&vec![7; 100_000]).encode().unwrap();
    let mut seen = Vec::new();
    let mut fed = 0;
    for part in all.chunks(1000) {
        for event in request.feed(part).unwrap() {
            let Event::Data(bytes) = event else {
                panic!("{event:?}");
            };
            seen.extend(bytes);
        }
        fed += part.len();
        assert_eq!(seen.len(), fed.saturating_sub(5), "{fed}");
    }
    assert_eq!(seen, vec![7; 100_000]);
    assert_eq!(request.end(), Ok(Event::End));
}

#[test]
fn steady() {
    let mut request = Request::new(64);
    request.feed(&wire(&[head(b"h")])).unwrap();
    request.feed(&bytes("00 80 01 86 a0")).unwrap();
    for _ in 0..100 {
        let events = request.feed(&[5; 1000]).unwrap();
        assert_eq!(events, vec![Event::Data(vec![5; 1000])]);
    }
    assert_eq!(request.end(), Ok(Event::End));
}

#[test]
fn empty() {
    let events = run(&[head(b"h"), data(b""), data(b"x")]).unwrap();
    let expected = vec![
        Event::Headers(b"h".to_vec()),
        Event::Data(Vec::new()),
        Event::Data(b"x".to_vec()),
    ];
    assert_eq!(events, expected);
}

#[test]
fn splits() {
    let frames = [
        head(b"hh"),
        data(&[1; 300]),
        data(b"abcde"),
        grease(0x21, 4),
        data(b"1234567"),
        head(b"tt"),
    ];
    let input = wire(&frames);
    let whole = merged(Request::new(64).feed(&input).unwrap());
    assert_eq!(whole.len(), 3);
    let mut bytewise = Request::new(64);
    let mut seen = Vec::new();
    for byte in &input {
        seen.extend(bytewise.feed(&[*byte]).unwrap());
    }
    assert_eq!(merged(seen), whole);
    for seed in 1..=60u64 {
        let mut dice = Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut request = Request::new(64);
        let mut seen = Vec::new();
        let mut at = 0;
        while at < input.len() {
            let end = (at + 1 + dice.roll(50) as usize).min(input.len());
            seen.extend(request.feed(&input[at..end]).unwrap());
            at = end;
        }
        assert_eq!(merged(seen), whole, "seed {seed}");
        assert_eq!(request.end(), Ok(Event::End));
    }
}

#[test]
fn interim() {
    let events = run(&[head(b"1"), head(b"2"), head(b"3"), data(b"d"), head(b"t")]).unwrap();
    let expected = vec![
        Event::Headers(b"1".to_vec()),
        Event::Headers(b"2".to_vec()),
        Event::Headers(b"3".to_vec()),
        Event::Data(b"d".to_vec()),
        Event::Trailers(b"t".to_vec()),
    ];
    assert_eq!(events, expected);
    let bare = run(&[head(b"1"), head(b"2")]).unwrap();
    assert_eq!(bare.len(), 2);
    assert!(bare.iter().all(|event| matches!(event, Event::Headers(_))));
}

#[test]
fn invalid() {
    let unexpected = connection(Code::Unexpected);
    let cases = [
        vec![data(b"d")],
        vec![head(b"h"), data(b"d"), head(b"t"), head(b"u")],
        vec![head(b"h"), data(b"d"), head(b"t"), data(b"d")],
        vec![head(b"h"), data(b"d"), head(b"t"), data(b"")],
    ];
    for frames in cases {
        assert_eq!(run(&frames), Err(unexpected), "{frames:?}");
    }
    let others = [
        Frame::Settings(Settings::default()),
        Frame::Goaway(0),
        Frame::Cancel(0),
        Frame::Max(0),
    ];
    for other in others {
        let prefixes = [vec![], vec![head(b"h")], vec![head(b"h"), data(b"d")]];
        for mut frames in prefixes {
            frames.push(other.clone());
            assert_eq!(run(&frames), Err(unexpected), "{frames:?}");
        }
    }
}

#[test]
fn pushes() {
    let promise = Frame::Promise {
        push: 0,
        block: vec![0],
    };
    let id = connection(Code::Id);
    let prefixes = [
        vec![],
        vec![head(b"h")],
        vec![head(b"h"), data(b"d"), head(b"t")],
    ];
    for mut frames in prefixes {
        frames.push(promise.clone());
        assert_eq!(run(&frames), Err(id), "{frames:?}");
    }
}

#[test]
fn reserved() {
    for kind in ["02", "06", "08", "09"] {
        let mut request = Request::new(64);
        let bad = bytes(&format!("{kind} 00"));
        let fault = request.feed(&bad).unwrap_err();
        assert_eq!(fault, connection(Code::Unexpected), "{kind}");
        let mut later = Request::new(64);
        later.feed(&wire(&[head(b"h")])).unwrap();
        assert_eq!(later.feed(&bad), Err(connection(Code::Unexpected)));
    }
}

#[test]
fn unknown() {
    let frames = [
        grease(0x21, 2),
        head(b"h"),
        grease(0x40, 0),
        data(b"d"),
        grease(0x5f, 9),
        head(b"t"),
        grease(0x21, 1),
    ];
    let events = run(&frames).unwrap();
    let expected = vec![
        Event::Headers(b"h".to_vec()),
        Event::Data(b"d".to_vec()),
        Event::Trailers(b"t".to_vec()),
    ];
    assert_eq!(events, expected);
    assert_eq!(run(&lone(grease(0x21, 3))).unwrap(), Vec::new());
}

#[test]
fn truncated() {
    let frames = [
        head(b"abc"),
        data(b"hello"),
        grease(0x21, 4),
        data(b""),
        head(b"t"),
    ];
    let input = wire(&frames);
    let mut bounds = vec![0];
    for frame in &frames {
        let last = *bounds.last().unwrap();
        bounds.push(last + frame.encode().unwrap().len());
    }
    for cut in 0..=input.len() {
        let mut request = Request::new(64);
        request.feed(&input[..cut]).unwrap();
        let ended = request.end();
        if bounds.contains(&cut) {
            assert_eq!(ended, Ok(Event::End), "{cut}");
        } else {
            assert_eq!(ended, Err(connection(Code::Frame)), "{cut}");
        }
    }
}

#[test]
fn heavy() {
    let mut request = Request::new(64);
    let fault = request.feed(&bytes("01 40 41")).unwrap_err();
    assert_eq!(fault, connection(Code::Load));
    let mut fine = Request::new(64);
    let mut input = wire(&[head(b"h")]);
    input.extend(bytes("00 40 41"));
    input.extend([1; 65]);
    assert_eq!(fine.feed(&input).unwrap().len(), 2);
}

#[test]
fn malformed() {
    let bad = bytes("03 02 05 06");
    let fault = Request::new(64).feed(&bad).unwrap_err();
    assert_eq!(fault, connection(Code::Frame));
    let mut later = Request::new(64);
    later.feed(&wire(&[head(b"h")])).unwrap();
    assert_eq!(later.feed(&bad), Err(connection(Code::Frame)));
}
