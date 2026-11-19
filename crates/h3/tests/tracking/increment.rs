use crate::support::*;
use h3::{Error, Feedback};

#[test]
fn zero() {
    let mut tracker = tracker(350, 1, 3);
    let outcome = tracker.feedback(Feedback::Increment(0));
    assert_eq!(outcome, Err(Error::Zero));
    assert_eq!(tracker.known(), 0);
}

#[test]
fn excess() {
    let mut tracker = tracker(350, 1, 3);
    let outcome = tracker.feedback(Feedback::Increment(4));
    assert_eq!(outcome, Err(Error::Feedback));
    assert_eq!(tracker.known(), 0);
    let outcome = tracker.feedback(Feedback::Increment(u64::MAX));
    assert_eq!(outcome, Err(Error::Feedback));
    tracker.feedback(Feedback::Increment(3)).unwrap();
    assert_eq!(tracker.known(), 3);
    let outcome = tracker.feedback(Feedback::Increment(1));
    assert_eq!(outcome, Err(Error::Feedback));
    assert_eq!(tracker.known(), 3);
}

#[test]
fn partial() {
    let mut tracker = tracker(350, 1, 3);
    tracker.feedback(Feedback::Increment(2)).unwrap();
    assert_eq!(tracker.known(), 2);
    tracker.feedback(Feedback::Increment(1)).unwrap();
    assert_eq!(tracker.known(), 3);
}

#[test]
fn steady() {
    let mut tracker = tracker(350, 1, 3);
    section(&mut tracker, 4, &[0]).unwrap();
    tracker.feedback(Feedback::Increment(3)).unwrap();
    tracker.feedback(Feedback::Acknowledge(4)).unwrap();
    assert_eq!(tracker.known(), 3);
}

#[test]
fn unblocks() {
    let mut tracker = tracker(350, 1, 3);
    section(&mut tracker, 4, &[2]).unwrap();
    assert_eq!(tracker.blocked(), 1);
    tracker.feedback(Feedback::Increment(2)).unwrap();
    assert_eq!(tracker.blocked(), 1);
    tracker.feedback(Feedback::Increment(1)).unwrap();
    assert_eq!(tracker.blocked(), 0);
    assert_eq!(tracker.outstanding(4), 1);
}

fn stream() -> Vec<Feedback> {
    vec![
        Feedback::Increment(1),
        Feedback::Acknowledge(4),
        Feedback::Cancel(8),
        Feedback::Increment(2),
    ]
}

fn prepared() -> h3::Tracker {
    let mut tracker = tracker(350, 4, 4);
    section(&mut tracker, 4, &[1]).unwrap();
    section(&mut tracker, 8, &[3]).unwrap();
    tracker
}

#[test]
fn bytes() {
    let mut single = prepared();
    for feedback in stream() {
        single.feedback(feedback).unwrap();
    }
    let wire: Vec<u8> = stream()
        .iter()
        .flat_map(|feedback| feedback.encode().unwrap())
        .collect();
    let mut whole = prepared();
    assert_eq!(whole.receive(&wire), Ok(wire.len()));
    let state = |tracker: &h3::Tracker| {
        format!(
            "{} {} {} {}",
            tracker.known(),
            tracker.outstanding(4),
            tracker.outstanding(8),
            tracker.blocked()
        )
    };
    assert_eq!(state(&whole), state(&single));
    for cut in 0..=wire.len() {
        let mut split = prepared();
        let first = split.receive(&wire[..cut]).unwrap();
        let rest: Vec<u8> = wire[first..].to_vec();
        assert_eq!(split.receive(&rest), Ok(rest.len()), "{cut}");
        assert_eq!(state(&split), state(&single), "{cut}");
    }
}

#[test]
fn invalid() {
    let mut tracker = prepared();
    assert_eq!(tracker.receive(&[0x00]), Err(Error::Zero));
    let mut tracker = prepared();
    let mut wire = Feedback::Increment(1).encode().unwrap();
    wire.extend(Feedback::Increment(10).encode().unwrap());
    assert_eq!(tracker.receive(&wire), Err(Error::Feedback));
    assert_eq!(tracker.known(), 1);
}
