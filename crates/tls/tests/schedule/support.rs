use crypto::Hash;
use tls::{Master, Schedule};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn schedule(shared: &str) -> Schedule {
    Schedule::new(Hash::Sha256, &hex(shared)).unwrap()
}

pub fn master(shared: &str) -> Master {
    schedule(shared).master().unwrap()
}
