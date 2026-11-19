use h3::{Field, Instruction, Name, Tracker};

pub fn field(name: &str, value: &str) -> Field {
    Field::new(name.as_bytes(), value.as_bytes())
}

pub fn put(name: &str, value: &str) -> Instruction {
    Instruction::Insert {
        name: Name::Literal(name.as_bytes().to_vec()),
        value: value.as_bytes().to_vec(),
    }
}

pub fn tracker(capacity: usize, blocked: usize, entries: usize) -> Tracker {
    let mut tracker = Tracker::new(capacity, blocked);
    tracker
        .apply(&Instruction::Capacity(capacity as u64))
        .unwrap();
    for number in 0..entries {
        tracker.apply(&put(&format!("k{number}"), "v")).unwrap();
    }
    tracker
}

pub fn section(tracker: &mut Tracker, stream: u64, cited: &[u64]) -> Result<u64, h3::Error> {
    for absolute in cited {
        tracker.cite(*absolute)?;
    }
    tracker.sent(stream)
}

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}
