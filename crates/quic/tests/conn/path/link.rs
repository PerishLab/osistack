use crate::support::token;
use quic::{Amplify, Echo, Frame, Path, Recovery, Sent, Space, Validity};

fn carry(frame: Frame) -> Frame {
    let bytes = Frame::join(&[frame]).unwrap();
    let mut all = Frame::all(&bytes).unwrap();
    assert_eq!(all.len(), 1);
    all.remove(0)
}

fn answer(echo: &mut Echo, frame: Frame, room: u64) -> Option<(Frame, bool)> {
    let Frame::Challenge(data) = carry(frame) else {
        return None;
    };
    assert!(echo.challenge(data));
    let probe = echo.next(room)?;
    Some((carry(Frame::Response(probe.token)), probe.expand))
}

fn verify(path: &mut Path, frame: Frame) -> bool {
    match carry(frame) {
        Frame::Response(data) => path.response(data),
        _ => false,
    }
}

#[test]
fn migrate() {
    let mut path = Path::new(0);
    let mut echo = Echo::default();
    let probe = path.challenge(0, token(1), u64::MAX).unwrap();
    let (reply, expand) = answer(&mut echo, Frame::Challenge(probe.token), u64::MAX).unwrap();
    assert!(expand);
    assert_eq!(reply, Frame::Response(token(1)));
    assert!(verify(&mut path, reply));
    assert_eq!(path.validity(), Validity::Valid);
    assert!(path.mtu());
}

#[test]
fn lossy() {
    let mut path = Path::new(0);
    let mut echo = Echo::default();
    path.challenge(0, token(1), u64::MAX).unwrap();
    let probe = path.challenge(1_000_000, token(2), u64::MAX).unwrap();
    let (reply, _) = answer(&mut echo, Frame::Challenge(probe.token), u64::MAX).unwrap();
    assert!(verify(&mut path, reply));
    assert_eq!(path.validity(), Validity::Valid);
    assert_eq!(echo.pending(), 0);
}

#[test]
fn hole() {
    let mut path = Path::new(300_000);
    path.challenge(50, token(1), u64::MAX).unwrap();
    path.challenge(1_000_000, token(2), u64::MAX).unwrap();
    path.challenge(2_000_000, token(3), u64::MAX).unwrap();
    let due = path.deadline().unwrap();
    assert_eq!(due, 50 + 2_997_000);
    assert!(!path.expire(due - 1));
    assert!(path.expire(due));
    assert_eq!(path.validity(), Validity::Failed);
}

#[test]
fn routed() {
    let mut first = Path::new(0);
    let mut second = Path::new(0);
    let mut near = Echo::default();
    let mut far = Echo::default();
    let one = first.challenge(0, token(1), u64::MAX).unwrap();
    let two = second.challenge(0, token(2), u64::MAX).unwrap();
    let (back, _) = answer(&mut far, Frame::Challenge(two.token), u64::MAX).unwrap();
    let (reply, _) = answer(&mut near, Frame::Challenge(one.token), u64::MAX).unwrap();
    assert!(!verify(&mut second, reply.clone()));
    assert_eq!(second.validity(), Validity::Pending);
    assert!(verify(&mut first, reply));
    assert_eq!(first.validity(), Validity::Valid);
    assert_eq!(second.validity(), Validity::Pending);
    assert!(verify(&mut second, back));
    assert_eq!(second.validity(), Validity::Valid);
}

#[test]
fn stages() {
    let mut amplify = Amplify::new(false);
    let mut path = Path::new(0);
    let mut echo = Echo::default();
    amplify.receive(100);
    let probe = path.challenge(0, token(1), amplify.room()).unwrap();
    assert!(!probe.expand);
    assert!(amplify.send(60));
    let (reply, expand) = answer(&mut echo, Frame::Challenge(probe.token), u64::MAX).unwrap();
    assert!(expand);
    assert!(verify(&mut path, reply));
    assert_eq!(path.validity(), Validity::Valid);
    assert!(!path.mtu());
    amplify.validate();
    assert_eq!(amplify.room(), u64::MAX);
    let probe = path.challenge(500, token(2), amplify.room()).unwrap();
    assert!(probe.expand);
    let (reply, _) = answer(&mut echo, Frame::Challenge(probe.token), u64::MAX).unwrap();
    assert!(verify(&mut path, reply));
    assert!(path.mtu());
}

#[test]
fn limit() {
    let mut recovery = Recovery::new(true, 25_000, 3);
    let mut amplify = Amplify::new(false);
    amplify.receive(1200);
    for number in 0..3 {
        assert!(amplify.send(1200));
        let packet = Sent {
            number,
            time: number * 10,
            size: 1200,
            eliciting: true,
            flight: true,
        };
        recovery.sent(Space::Initial, packet);
        if number == 0 {
            assert!(recovery.deadline().is_some());
        }
    }
    assert!(amplify.blocked());
    recovery.limit(100, amplify.blocked());
    assert_eq!(recovery.deadline(), None);
    amplify.receive(1200);
    assert!(!amplify.blocked());
    recovery.limit(200, amplify.blocked());
    assert!(recovery.deadline().is_some());
}
