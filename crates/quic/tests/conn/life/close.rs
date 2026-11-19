use quic::{Error, Frame, Life, Mode};

fn shut() -> Frame {
    Frame::Application {
        code: 7,
        reason: b"bye".to_vec(),
    }
}

fn fault() -> Frame {
    Frame::Transport {
        code: 10,
        frame: 6,
        reason: Vec::new(),
    }
}

fn closing() -> Life {
    let mut life = Life::default();
    life.close(100, 1_000, shut()).unwrap();
    life
}

fn draining() -> Life {
    let mut life = Life::default();
    life.peer(100, 1_000);
    life
}

#[test]
fn open() {
    let mut life = Life::default();
    assert_eq!(life.mode(), Mode::Open);
    assert_eq!(life.deadline(), None);
    assert_eq!(life.frame(), None);
    assert_eq!(life.receive(), None);
    assert!(!life.expire(u64::MAX));
    assert_eq!(life.mode(), Mode::Open);
}

#[test]
fn entered() {
    let life = closing();
    assert_eq!(life.mode(), Mode::Closing);
    assert_eq!(life.deadline(), Some(3_100));
    assert_eq!(life.frame(), Some(&shut()));
}

#[test]
fn reject() {
    for frame in [
        Frame::Ping,
        Frame::Done,
        Frame::Padding(1),
        Frame::Blocked(0),
    ] {
        let mut life = Life::default();
        assert_eq!(life.close(0, 1, frame), Err(Error::Value));
        assert_eq!(life.mode(), Mode::Open);
        assert_eq!(life.deadline(), None);
    }
    let mut life = closing();
    assert_eq!(life.close(200, 1, fault()), Err(Error::Value));
    assert_eq!(life.mode(), Mode::Closing);
    assert_eq!(life.deadline(), Some(3_100));
    assert_eq!(life.frame(), Some(&shut()));
}

#[test]
fn kinds() {
    let mut life = Life::default();
    assert_eq!(life.close(0, 1, fault()), Ok(()));
    assert_eq!(life.frame(), Some(&fault()));
    let mut life = Life::default();
    assert_eq!(life.close(0, 1, shut()), Ok(()));
    assert_eq!(life.frame(), Some(&shut()));
}

#[test]
fn reply() {
    let mut life = closing();
    for count in 1..=40u64 {
        let got = life.receive().cloned();
        if count.is_power_of_two() {
            assert_eq!(got, Some(shut()), "packet {count}");
        } else {
            assert_eq!(got, None, "packet {count}");
        }
    }
}

#[test]
fn quiet() {
    let mut life = Life::default();
    assert_eq!(life.receive(), None);
    let mut life = draining();
    for _ in 0..5 {
        assert_eq!(life.receive(), None);
    }
    assert!(life.expire(5_000));
    assert_eq!(life.receive(), None);
    let mut life = closing();
    assert!(life.expire(5_000));
    assert_eq!(life.receive(), None);
}

#[test]
fn drain() {
    let mut life = draining();
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.deadline(), Some(3_100));
    assert_eq!(life.frame(), None);
    assert_eq!(life.receive(), None);
}

#[test]
fn shared() {
    let mut life = closing();
    life.peer(2_000, 5_000);
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.deadline(), Some(3_100));
    assert_eq!(life.frame(), None);
}

#[test]
fn steady() {
    let mut life = draining();
    life.peer(5_000, 9_999);
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.deadline(), Some(3_100));
    assert_eq!(life.close(5_000, 1, shut()), Err(Error::Value));
    assert_eq!(life.mode(), Mode::Draining);
}

#[test]
fn expire() {
    let mut life = closing();
    assert!(!life.expire(3_099));
    assert_eq!(life.mode(), Mode::Closing);
    assert!(life.expire(3_100));
    assert_eq!(life.mode(), Mode::Closed);
    assert_eq!(life.deadline(), None);
    assert_eq!(life.frame(), None);
    assert!(!life.expire(9_999));
    let mut life = draining();
    assert!(!life.expire(3_099));
    assert_eq!(life.mode(), Mode::Draining);
    assert!(life.expire(3_100));
    assert_eq!(life.mode(), Mode::Closed);
    assert!(!life.expire(9_999));
}

#[test]
fn silent() {
    let mut life = Life::default();
    life.idle();
    assert_eq!(life.mode(), Mode::Closed);
    assert_eq!(life.deadline(), None);
    let mut life = closing();
    life.idle();
    assert_eq!(life.mode(), Mode::Closing);
    let mut life = draining();
    life.idle();
    assert_eq!(life.mode(), Mode::Draining);
    let mut life = closing();
    life.expire(9_999);
    life.idle();
    assert_eq!(life.mode(), Mode::Closed);
}

#[test]
fn closed() {
    let mut life = Life::default();
    life.idle();
    assert_eq!(life.close(0, 1, shut()), Err(Error::Value));
    life.peer(0, 1);
    life.reset(0, 1);
    assert_eq!(life.mode(), Mode::Closed);
    assert_eq!(life.deadline(), None);
    assert_eq!(life.frame(), None);
}

#[test]
fn triple() {
    let mut life = Life::default();
    life.close(0, 0, shut()).unwrap();
    assert_eq!(life.deadline(), Some(0));
    assert!(life.expire(0));
    let mut life = Life::default();
    life.close(5, 7, shut()).unwrap();
    assert_eq!(life.deadline(), Some(26));
    let mut life = Life::default();
    life.peer(5, 7);
    assert_eq!(life.deadline(), Some(26));
}

#[test]
fn saturate() {
    let mut life = Life::default();
    life.close(u64::MAX, 1, shut()).unwrap();
    assert_eq!(life.deadline(), Some(u64::MAX));
    let mut life = Life::default();
    life.close(1, u64::MAX, shut()).unwrap();
    assert_eq!(life.deadline(), Some(u64::MAX));
    let mut life = Life::default();
    life.peer(u64::MAX, u64::MAX);
    assert_eq!(life.deadline(), Some(u64::MAX));
}
