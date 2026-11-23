use crate::error::Error;
use crate::qpack::field::Field;
use crate::qpack::section::Section;
use crate::qpack::tables::{Dynamic, Found, Table};
use wire::{Huffman, Packed, Writer};

const STATIC: Packed = Packed::valid(6, 0xc0);
const NAMED: Packed = Packed::valid(4, 0x50);
const HIDDEN: Packed = Packed::valid(4, 0x70);
const LATER: Packed = Packed::valid(4, 0x10);
const PRIOR: Packed = Packed::valid(6, 0x80);
const OPEN: Packed = Packed::valid(3, 0);
const POST: Packed = Packed::valid(3, 0x08);
const LEFT: Packed = Packed::valid(4, 0x40);
const HELD: Packed = Packed::valid(4, 0x60);
const SPELL: Packed = Packed::valid(3, 0x20);
const COVER: Packed = Packed::valid(3, 0x28);
const MASKED: Packed = Packed::valid(3, 0x30);
const CODED: Packed = Packed::valid(3, 0x38);
const INDEX: Packed = Packed::valid(7, 0x80);
const RAW: Packed = Packed::valid(7, 0);

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
        self.trace((table, base, u64::MAX), fields)
            .map(|(block, _)| block)
    }

    pub fn trace(
        &self,
        view: (&Dynamic, u64, u64),
        fields: &[Field],
    ) -> Result<(Vec<u8>, Vec<u64>), Error> {
        let (table, base, _) = view;
        if base > table.inserted() {
            return Err(Error::Base);
        }
        let mut body = Writer::new();
        let mut cited = Vec::new();
        for field in fields {
            cited.extend(self.cite(&mut body, view, field));
        }
        let required = cited.iter().max().map_or(0, |absolute| absolute + 1);
        let section = Section {
            required,
            base: if required == 0 { 0 } else { base },
        };
        let mut head = Writer::new();
        section.write(&mut head, table.maximum())?;
        head.put(&body.finish());
        Ok((head.finish(), cited))
    }

    fn cite(&self, writer: &mut Writer, view: (&Dynamic, u64, u64), field: &Field) -> Option<u64> {
        let (table, base, bound) = view;
        let seen = Self::seek(table, bound, field);
        let fixed = Table::find(field);
        let secret = field.sensitive;
        if let (Found::Full(index), false) = (fixed, secret) {
            Self::integer(writer, STATIC, index);
            return None;
        }
        if let (Some(absolute), false) = (seen.full, secret) {
            Self::point(writer, absolute, base);
            return Some(absolute);
        }
        if let Found::Full(index) | Found::Name(index) = fixed {
            Self::integer(writer, if secret { HIDDEN } else { NAMED }, index);
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

    fn seek(table: &Dynamic, bound: u64, field: &Field) -> Seen {
        let dropped = table.dropped();
        let mut seen = Seen {
            full: None,
            name: None,
        };
        for (offset, entry) in table.entries().iter().enumerate().rev() {
            let absolute = dropped + offset as u64;
            if absolute >= bound || entry.name != field.name {
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
            Some(after) => Self::integer(writer, LATER, after as usize),
            None => Self::integer(writer, PRIOR, (base - 1 - absolute) as usize),
        }
    }

    fn named(writer: &mut Writer, absolute: u64, view: (u64, bool)) {
        let (base, secret) = view;
        match absolute.checked_sub(base) {
            Some(after) => {
                let mark = if secret { POST } else { OPEN };
                Self::integer(writer, mark, after as usize);
            }
            None => {
                let mark = if secret { HELD } else { LEFT };
                Self::integer(writer, mark, (base - 1 - absolute) as usize);
            }
        }
    }

    fn field(&self, writer: &mut Writer, field: &Field) {
        let spelled = if field.sensitive { 0x30 } else { 0x20 };
        match Table::find(field) {
            Found::Full(index) if !field.sensitive => Self::integer(writer, STATIC, index),
            Found::Full(index) | Found::Name(index) => {
                Self::integer(writer, if field.sensitive { HIDDEN } else { NAMED }, index);
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
                Self::integer(
                    writer,
                    if high == 0x30 { CODED } else { COVER },
                    coded.len(),
                );
                writer.put(&coded);
            }
            None => {
                Self::integer(
                    writer,
                    if high == 0x30 { MASKED } else { SPELL },
                    name.len(),
                );
                writer.put(name);
            }
        }
    }

    fn string(&self, writer: &mut Writer, bytes: &[u8]) {
        match &self.huffman {
            Some(huffman) => {
                let coded = huffman.encode(bytes);
                Self::integer(writer, INDEX, coded.len());
                writer.put(&coded);
            }
            None => {
                Self::integer(writer, RAW, bytes.len());
                writer.put(bytes);
            }
        }
    }

    fn integer(writer: &mut Writer, packed: Packed, value: usize) {
        writer.packed(packed, value as u64);
    }
}
