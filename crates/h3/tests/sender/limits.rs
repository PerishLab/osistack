use crate::support::*;
use h3::{Error, Sender};

fn ready(blocked: usize, capacity: usize) -> Sender {
    let mut sender = Sender::new(1000, blocked, false);
    sender.capacity(capacity).unwrap();
    sender
}

#[test]
fn quiet() {
    let mut sender = ready(0, 1000);
    for number in 0..40u64 {
        let name = format!("k{}", number % 5);
        let value = (number % 3).to_string();
        let encoded = sender.encode(number * 4, &[field(&name, &value)]).unwrap();
        assert_eq!(encoded.block[0], 0, "{number}");
        assert_eq!(sender.tracker().blocked(), 0);
    }
    assert!(sender.tracker().table().inserted() > 0);
    let inserted = sender.tracker().table().inserted();
    sender.receive(&increment(inserted)).unwrap();
    let encoded = sender.encode(400, &[field("k0", "0")]).unwrap();
    assert_ne!(encoded.block[0], 0);
    assert_eq!(sender.tracker().blocked(), 0);
    assert_eq!(sender.tracker().outstanding(400), 1);
}

#[test]
fn gate() {
    let mut sender = ready(1, 1000);
    let fields = [field("x-a", "1")];
    sender.encode(4, &fields).unwrap();
    assert_eq!(sender.tracker().blocked(), 1);
    let second = sender.encode(8, &fields).unwrap();
    assert_eq!(second.block[0], 0);
    assert_eq!(sender.tracker().outstanding(8), 0);
    assert_eq!(sender.tracker().blocked(), 1);
    sender.receive(&ack(4)).unwrap();
    assert_eq!(sender.tracker().blocked(), 0);
    let third = sender.encode(12, &fields).unwrap();
    assert_ne!(third.block[0], 0);
    assert_eq!(sender.tracker().outstanding(12), 1);
    assert_eq!(sender.tracker().blocked(), 0);
}

#[test]
fn stalled() {
    let mut sender = ready(1, 1000);
    sender.encode(4, &[field("x-a", "1")]).unwrap();
    sender.encode(4, &[field("x-b", "1")]).unwrap();
    assert_eq!(sender.tracker().outstanding(4), 2);
    assert_eq!(sender.tracker().blocked(), 1);
    let other = sender.encode(8, &[field("x-c", "1")]).unwrap();
    assert_eq!(other.block[0], 0);
    assert_eq!(sender.tracker().outstanding(8), 0);
}

#[test]
fn pinned() {
    let mut sender = ready(4, 72);
    sender.encode(4, &[field("ka", "1")]).unwrap();
    sender.encode(8, &[field("kb", "1")]).unwrap();
    assert_eq!(sender.tracker().table().size(), 70);
    let third = sender.encode(12, &[field("kc", "1")]).unwrap();
    assert!(third.instructions.is_empty());
    assert_eq!(sender.tracker().table().inserted(), 2);
    assert_eq!(third.block, empty(&[field("kc", "1")]));
    sender.receive(&ack(4)).unwrap();
    let fourth = sender.encode(16, &[field("kc", "1")]).unwrap();
    assert!(!fourth.instructions.is_empty());
    assert_eq!(sender.tracker().table().inserted(), 3);
    assert_eq!(sender.tracker().table().dropped(), 1);
    assert!(sender.tracker().held(1));
}

#[test]
fn cancelled() {
    let mut sender = ready(4, 72);
    sender.encode(4, &[field("ka", "1")]).unwrap();
    sender.encode(8, &[field("kb", "1")]).unwrap();
    let blocked = sender.encode(12, &[field("kc", "1")]).unwrap();
    assert!(blocked.instructions.is_empty());
    sender.receive(&cancel(4)).unwrap();
    let after = sender.encode(16, &[field("kc", "1")]).unwrap();
    assert!(!after.instructions.is_empty());
    assert_eq!(sender.tracker().table().dropped(), 1);
}

#[test]
fn reach() {
    let mut sender = Sender::new(220, 8, false);
    sender.capacity(220).unwrap();
    for number in 0..6u64 {
        let name = format!("k{number}");
        sender.encode(number * 4, &[field(&name, "1")]).unwrap();
        assert_eq!(sender.tracker().outstanding(number * 4), 1);
    }
    sender.receive(&cancel(0)).unwrap();
    let wide = sender.encode(24, &[field("k6", "1")]).unwrap();
    assert!(!wide.instructions.is_empty());
    assert_eq!(wide.block[0], 0);
    assert_eq!(sender.tracker().outstanding(24), 0);
    assert_eq!(sender.tracker().table().inserted(), 7);
    sender.receive(&increment(1)).unwrap();
    let near = sender.encode(28, &[field("k6", "1")]).unwrap();
    assert!(near.instructions.is_empty());
    assert_ne!(near.block[0], 0);
    assert_eq!(sender.tracker().outstanding(28), 1);
}

#[test]
fn feedback() {
    let mut sender = ready(1, 1000);
    assert_eq!(sender.receive(&ack(4)), Err(Error::Feedback));
}
