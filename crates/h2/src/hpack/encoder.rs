use super::header::Header;
use super::table::{Found, Table};
use wire::{Huffman, Packed, Writer};

const SIZE: Packed = Packed::valid(5, 0x20);
const INDEX: Packed = Packed::valid(7, 0x80);
const NEVER: Packed = Packed::valid(4, 0x10);
const FRESH: Packed = Packed::valid(6, 0x40);
const RAW: Packed = Packed::valid(7, 0);

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
            Self::integer(writer, SIZE, size);
        }
    }

    fn field(&mut self, writer: &mut Writer, header: &Header) {
        let found = self.table.find(&header.name, &header.value);
        if let (Found::Full(index), false) = (found, header.sensitive) {
            return Self::integer(writer, INDEX, index);
        }
        let named = match found {
            Found::Full(index) | Found::Name(index) => index,
            Found::Absent => 0,
        };
        let mark = if header.sensitive { NEVER } else { FRESH };
        Self::integer(writer, mark, named);
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
