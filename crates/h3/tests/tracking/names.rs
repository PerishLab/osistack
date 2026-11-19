use crate::support::*;
use h3::{Decoder, Instruction, Name, Tracker};

fn add(name: Name, value: &str) -> Instruction {
    Instruction::Insert {
        name,
        value: value.as_bytes().to_vec(),
    }
}

fn script() -> Vec<Instruction> {
    vec![
        Instruction::Capacity(70),
        add(Name::Static(0), "www.example.com"),
        add(Name::Literal(b"k".to_vec()), "v"),
        add(Name::Dynamic(0), "w"),
    ]
}

#[test]
fn resolved() {
    let mut tracker = Tracker::new(200, 1);
    let mut decoder = Decoder::new(200);
    let mut sets = vec![Instruction::Capacity(200)];
    sets.extend(script().into_iter().skip(1));
    sets.push(add(Name::Dynamic(2), "again"));
    for instruction in sets {
        tracker.apply(&instruction).unwrap();
        decoder.apply(&instruction.encode(None).unwrap()).unwrap();
    }
    assert_eq!(tracker.table().entries(), decoder.table().entries());
    assert_eq!(
        tracker.table().get(0),
        Some(&field(":authority", "www.example.com"))
    );
    assert_eq!(tracker.table().get(2), Some(&field("k", "w")));
    assert_eq!(tracker.table().get(3), Some(&field(":authority", "again")));
}

#[test]
fn evicted() {
    let mut tracker = Tracker::new(70, 1);
    let mut decoder = Decoder::new(70);
    let sets = [
        Instruction::Capacity(70),
        add(Name::Literal(b"k0".to_vec()), "v"),
        add(Name::Literal(b"k1".to_vec()), "v"),
        add(Name::Dynamic(1), "w"),
    ];
    for instruction in sets {
        tracker.apply(&instruction).unwrap();
        decoder.apply(&instruction.encode(None).unwrap()).unwrap();
    }
    assert_eq!(tracker.table().dropped(), 1);
    assert_eq!(tracker.table().get(2), Some(&field("k0", "w")));
    assert_eq!(tracker.table().entries(), decoder.table().entries());
}

#[test]
fn missing() {
    let mut tracker = Tracker::new(200, 1);
    tracker.apply(&Instruction::Capacity(200)).unwrap();
    for name in [Name::Static(99), Name::Dynamic(0)] {
        let outcome = tracker.apply(&add(name, "v"));
        assert_eq!(outcome, Err(h3::Error::Index));
    }
    assert_eq!(tracker.table().inserted(), 0);
}
