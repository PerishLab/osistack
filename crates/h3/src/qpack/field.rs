#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub sensitive: bool,
}

impl Field {
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        Self {
            name: name.to_vec(),
            value: value.to_vec(),
            sensitive: false,
        }
    }

    pub fn secret(name: &[u8], value: &[u8]) -> Self {
        Self {
            sensitive: true,
            ..Self::new(name, value)
        }
    }
}
