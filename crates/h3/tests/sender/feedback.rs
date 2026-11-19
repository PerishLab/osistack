use crate::support::*;
use h3::{Error, Sender};

fn busy() -> Sender {
    let mut sender = Sender::new(1000, 4, false);
    sender.capacity(1000).unwrap();
    sender.encode(4, &[field("ka", "1")]).unwrap();
    sender.encode(8, &[field("kb", "1")]).unwrap();
    sender.encode(12, &[field("kc", "1")]).unwrap();
    sender
}

fn state(sender: &Sender) -> String {
    let tracker = sender.tracker();
    format!(
        "{} {} {} {} {}",
        tracker.known(),
        tracker.blocked(),
        tracker.outstanding(4),
        tracker.outstanding(8),
        tracker.outstanding(12)
    )
}

#[test]
fn applied() {
    let mut sender = busy();
    assert_eq!(state(&sender), "0 3 1 1 1");
    assert_eq!(sender.receive(&ack(4)), Ok(1));
    assert_eq!(state(&sender), "1 2 0 1 1");
    assert_eq!(sender.receive(&cancel(8)), Ok(1));
    assert_eq!(state(&sender), "1 1 0 0 1");
    assert_eq!(sender.receive(&increment(2)), Ok(1));
    assert_eq!(state(&sender), "3 0 0 0 1");
}

#[test]
fn invalid() {
    let mut sender = busy();
    assert_eq!(sender.receive(&ack(99)), Err(Error::Feedback));
    assert_eq!(sender.receive(&increment(4)), Err(Error::Feedback));
    assert_eq!(sender.receive(&[0x00]), Err(Error::Zero));
    assert_eq!(state(&sender), "0 3 1 1 1");
}

#[test]
fn split() {
    let mut wire = ack(4);
    wire.extend(cancel(8));
    wire.extend(increment(2));
    let mut whole = busy();
    assert_eq!(whole.receive(&wire), Ok(wire.len()));
    for cut in 0..=wire.len() {
        let mut sender = busy();
        let first = sender.receive(&wire[..cut]).unwrap();
        let rest = wire[first..].to_vec();
        assert_eq!(sender.receive(&rest), Ok(rest.len()), "{cut}");
        assert_eq!(state(&sender), state(&whole), "{cut}");
    }
}

#[test]
fn referenced() {
    let mut sender = busy();
    sender.receive(&ack(4)).unwrap();
    sender.receive(&increment(2)).unwrap();
    let encoded = sender
        .encode(16, &[field("ka", "1"), field("kc", "1")])
        .unwrap();
    assert!(encoded.instructions.is_empty());
    assert_ne!(encoded.block[0], 0);
    assert!(sender.tracker().held(2));
    assert_eq!(sender.tracker().known(), 3);
    assert_eq!(sender.tracker().blocked(), 0);
}
