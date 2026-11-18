use crate::header::Header;
use crate::table::{Found, Table};
use wire::{Huffman, Prefix, Writer};

#[derive(Debug, Clone)]
pub struct Encoder {
    table: Table,
    huffman: Option<Huffman>,
    pending: Vec<usize>,
}

impl Encoder {
    pub fn new(limit: usize, huffman: bool) -> Self {
        Self {
            table: Table::new(limit),
            huffman: huffman.then(Huffman::new),
            pending: Vec::new(),
        }
    }

    pub fn resize(&mut self, limit: usize) {
        self.table.resize(limit);
        self.pending.push(limit);
    }

    pub fn size(&self) -> usize {
        self.table.size()
    }

    pub fn dynamic(&self) -> Vec<Header> {
        self.table.entries()
    }

    pub fn encode(&mut self, headers: &[Header]) -> Vec<u8> {
        let mut writer = Writer::new();
        self.updates(&mut writer);
        for header in headers {
            self.field(&mut writer, header);
        }
        writer.finish()
    }

    fn updates(&mut self, writer: &mut Writer) {
        let sizes = std::mem::take(&mut self.pending);
        let kept = match (sizes.iter().min(), sizes.last()) {
            (Some(low), Some(last)) if low != last => vec![*low, *last],
            (_, Some(last)) => vec![*last],
            _ => Vec::new(),
        };
        for size in kept {
            Self::integer(writer, 5, 0x20, size);
        }
    }

    fn field(&mut self, writer: &mut Writer, header: &Header) {
        let found = self.table.find(&header.name, &header.value);
        if let (Found::Full(index), false) = (found, header.sensitive) {
            return Self::integer(writer, 7, 0x80, index);
        }
        let named = match found {
            Found::Full(index) | Found::Name(index) => index,
            Found::Absent => 0,
        };
        let (bits, high) = if header.sensitive {
            (4, 0x10)
        } else {
            (6, 0x40)
        };
        Self::integer(writer, bits, high, named);
        if named == 0 {
            self.string(writer, &header.name);
        }
        self.string(writer, &header.value);
        if !header.sensitive {
            self.table.add(header.clone());
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
