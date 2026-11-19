use h3::{Control, Frame, Going, Notice, Settings, Streams};

fn encoded(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .flat_map(|frame| frame.encode().unwrap())
        .collect()
}

fn joined() -> Control {
    let mut control = Control::new(1 << 16);
    control
        .feed(&encoded(&[Frame::Settings(Settings::default())]))
        .unwrap();
    control
}

fn apply(streams: &mut Streams, notices: Vec<Notice>) -> Vec<Vec<u64>> {
    notices
        .into_iter()
        .filter_map(|notice| match notice {
            Notice::Goaway(id) => Some(streams.goaway(id).unwrap()),
            Notice::Settings(_) => None,
        })
        .collect()
}

fn three() -> Streams {
    let mut streams = Streams::new();
    for _ in 0..5 {
        streams.open().unwrap();
    }
    streams
}

#[test]
fn whole() {
    let mut control = joined();
    let mut streams = three();
    let wire = encoded(&[Frame::Goaway(12), Frame::Goaway(4)]);
    assert_eq!(wire, vec![0x07, 0x01, 0x0c, 0x07, 0x01, 0x04]);
    let notices = control.feed(&wire).unwrap();
    let freed = apply(&mut streams, notices);
    assert_eq!(freed, vec![vec![12, 16], vec![4, 8]]);
    assert_eq!(streams.active(), vec![0]);
    assert_eq!(streams.open(), Err(Going(4)));
}

#[test]
fn bytewise() {
    let mut control = joined();
    let mut streams = three();
    let mut freed = Vec::new();
    for byte in encoded(&[Frame::Goaway(64), Frame::Goaway(8)]) {
        let notices = control.feed(&[byte]).unwrap();
        freed.extend(apply(&mut streams, notices));
    }
    assert_eq!(freed, vec![vec![], vec![8, 12, 16]]);
    assert_eq!(streams.going(), Some(8));
    assert_eq!(streams.active(), vec![0, 4]);
}

#[test]
fn rejected() {
    let mut control = joined();
    let mut streams = three();
    let notices = control.feed(&encoded(&[Frame::Goaway(8)])).unwrap();
    apply(&mut streams, notices);
    assert_eq!(streams.open(), Err(Going(8)));
    assert!(control.feed(&encoded(&[Frame::Goaway(12)])).is_err());
    assert_eq!(streams.going(), Some(8));
}
