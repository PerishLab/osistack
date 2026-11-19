use h3::{Dynamic, Encoder, Feedback, Field, Instruction, Name};

pub fn field(name: &str, value: &str) -> Field {
    Field::new(name.as_bytes(), value.as_bytes())
}

pub fn secret(name: &str, value: &str) -> Field {
    Field::secret(name.as_bytes(), value.as_bytes())
}

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn put(name: Name, value: &str) -> Vec<u8> {
    let value = value.as_bytes().to_vec();
    Instruction::Insert { name, value }.encode(None).unwrap()
}

pub fn literal(name: &str) -> Name {
    Name::Literal(name.as_bytes().to_vec())
}

pub fn empty(fields: &[Field]) -> Vec<u8> {
    let table = Dynamic::new(0);
    Encoder::new(false).reference(&table, 0, fields).unwrap()
}

pub fn ack(stream: u64) -> Vec<u8> {
    Feedback::Acknowledge(stream).encode().unwrap()
}

pub fn cancel(stream: u64) -> Vec<u8> {
    Feedback::Cancel(stream).encode().unwrap()
}

pub fn increment(count: u64) -> Vec<u8> {
    Feedback::Increment(count).encode().unwrap()
}
