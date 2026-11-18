use crate::field::Field;
use crate::statics::STATIC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    Full(usize),
    Name(usize),
    Absent,
}

pub struct Table;

impl Table {
    pub fn get(index: usize) -> Option<Field> {
        STATIC
            .get(index)
            .map(|(name, value)| Field::new(name.as_bytes(), value.as_bytes()))
    }

    pub fn find(field: &Field) -> Found {
        let mut first = None;
        for (index, (name, value)) in STATIC.iter().enumerate() {
            if name.as_bytes() != field.name {
                continue;
            }
            if value.as_bytes() == field.value {
                return Found::Full(index);
            }
            first = first.or(Some(index));
        }
        first.map_or(Found::Absent, Found::Name)
    }
}
