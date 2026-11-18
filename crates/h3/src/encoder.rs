use crate::field::Field;
use crate::table::{Found, Table};
use wire::{Huffman, Prefix, Writer};

#[derive(Debug, Clone)]
pub struct Encoder {
    huffman: Option<Huffman>,
}

impl Encoder {
    pub fn new(huffman: bool) -> Self {
        Self {
            huffman: huffman.then(Huffman::new),
        }
    }

    pub fn encode(&self, fields: &[Field]) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.put(&[0, 0]);
        for field in fields {
            self.field(&mut writer, field);
        }
        writer.finish()
    }

    fn field(&self, writer: &mut Writer, field: &Field) {
        let (named, spelled) = if field.sensitive {
            (0x70, 0x30)
        } else {
            (0x50, 0x20)
        };
        match Table::find(field) {
            Found::Full(index) if !field.sensitive => Self::integer(writer, 6, 0xc0, index),
            Found::Full(index) | Found::Name(index) => {
                Self::integer(writer, 4, named, index);
                self.string(writer, &field.value);
            }
            Found::Absent => {
                self.literal(writer, spelled, &field.name);
                self.string(writer, &field.value);
            }
        }
    }

    fn literal(&self, writer: &mut Writer, high: u8, name: &[u8]) {
        match &self.huffman {
            Some(huffman) => {
                let coded = huffman.encode(name);
                Self::integer(writer, 3, high | 0x08, coded.len());
                writer.put(&coded);
            }
            None => {
                Self::integer(writer, 3, high, name.len());
                writer.put(name);
            }
        }
    }

    fn string(&self, writer: &mut Writer, bytes: &[u8]) {
        match &self.huffman {
            Some(huffman) => {
                let coded = huffman.encode(bytes);
                Self::integer(writer, 7, 0x80, coded.len());
                writer.put(&coded);
            }
            None => {
                Self::integer(writer, 7, 0, bytes.len());
                writer.put(bytes);
            }
        }
    }

    fn integer(writer: &mut Writer, bits: u8, high: u8, value: usize) {
        let prefix = Prefix::new(bits).expect("prefix width is fixed");
        writer
            .prefixed(prefix, high, value as u64)
            .expect("prefixed integer fits");
    }
}
