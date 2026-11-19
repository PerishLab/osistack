use h3::{Decoder, Dynamic, Field, Instruction, Name};

pub fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&clean[at..at + 2], 16).unwrap())
        .collect()
}

pub fn field(name: &str, value: &str) -> Field {
    Field::new(name.as_bytes(), value.as_bytes())
}

pub fn secret(name: &str, value: &str) -> Field {
    Field::secret(name.as_bytes(), value.as_bytes())
}

pub fn insert(name: &str, value: &str) -> Vec<u8> {
    let name = Name::Literal(name.as_bytes().to_vec());
    let value = value.as_bytes().to_vec();
    Instruction::Insert { name, value }.encode(None).unwrap()
}

pub fn capacity(size: u64) -> Vec<u8> {
    Instruction::Capacity(size).encode(None).unwrap()
}

pub fn table(maximum: usize, entries: &[(&str, &str)]) -> Dynamic {
    let mut table = Dynamic::new(maximum);
    table.resize(maximum).unwrap();
    for (name, value) in entries {
        table.insert(field(name, value)).unwrap();
    }
    table
}

pub fn decoder(maximum: usize, blocked: usize, entries: &[(&str, &str)]) -> Decoder {
    let mut decoder = Decoder::new(maximum).blocked(blocked);
    let mut bytes = capacity(maximum as u64);
    for (name, value) in entries {
        bytes.extend(insert(name, value));
    }
    assert_eq!(decoder.apply(&bytes).unwrap(), bytes.len());
    decoder
}
