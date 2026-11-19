use crate::error::Error;
use crate::qpack::field::Field;
use crate::qpack::section::Section;
use crate::qpack::tables::{Dynamic, Found, Table};
use wire::{Huffman, Prefix, Writer};

struct Seen {
    full: Option<u64>,
    name: Option<u64>,
}

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

    pub fn reference(
        &self,
        table: &Dynamic,
        base: u64,
        fields: &[Field],
    ) -> Result<Vec<u8>, Error> {
        if base > table.inserted() {
            return Err(Error::Base);
        }
        let mut body = Writer::new();
        let mut required = 0;
        for field in fields {
            let used = self.cite(&mut body, (table, base), field);
            required = required.max(used.map_or(0, |absolute| absolute + 1));
        }
        let section = Section {
            required,
            base: if required == 0 { 0 } else { base },
        };
        let mut head = Writer::new();
        section.write(&mut head, table.maximum())?;
        head.put(&body.finish());
        Ok(head.finish())
    }

    fn cite(&self, writer: &mut Writer, view: (&Dynamic, u64), field: &Field) -> Option<u64> {
        let (table, base) = view;
        let seen = Self::seek(table, field);
        let fixed = Table::find(field);
        let secret = field.sensitive;
        if let (Found::Full(index), false) = (fixed, secret) {
            Self::integer(writer, 6, 0xc0, index);
            return None;
        }
        if let (Some(absolute), false) = (seen.full, secret) {
            Self::point(writer, absolute, base);
            return Some(absolute);
        }
        let flag = if secret { 0x20 } else { 0 };
        if let Found::Full(index) | Found::Name(index) = fixed {
            Self::integer(writer, 4, 0x50 | flag, index);
            self.string(writer, &field.value);
            return None;
        }
        if let Some(absolute) = seen.name {
            Self::named(writer, absolute, (base, secret));
            self.string(writer, &field.value);
            return Some(absolute);
        }
        let spelled = if secret { 0x30 } else { 0x20 };
        self.literal(writer, spelled, &field.name);
        self.string(writer, &field.value);
        None
    }

    fn seek(table: &Dynamic, field: &Field) -> Seen {
        let dropped = table.dropped();
        let mut seen = Seen {
            full: None,
            name: None,
        };
        for (offset, entry) in table.entries().iter().enumerate().rev() {
            let absolute = dropped + offset as u64;
            if entry.name != field.name {
                continue;
            }
            seen.name = seen.name.or(Some(absolute));
            if entry.value == field.value {
                seen.full = Some(absolute);
                break;
            }
        }
        seen
    }

    fn point(writer: &mut Writer, absolute: u64, base: u64) {
        match absolute.checked_sub(base) {
            Some(after) => Self::integer(writer, 4, 0x10, after as usize),
            None => Self::integer(writer, 6, 0x80, (base - 1 - absolute) as usize),
        }
    }

    fn named(writer: &mut Writer, absolute: u64, view: (u64, bool)) {
        let (base, secret) = view;
        match absolute.checked_sub(base) {
            Some(after) => {
                let high = if secret { 0x08 } else { 0 };
                Self::integer(writer, 3, high, after as usize);
            }
            None => {
                let high = if secret { 0x60 } else { 0x40 };
                Self::integer(writer, 4, high, (base - 1 - absolute) as usize);
            }
        }
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
