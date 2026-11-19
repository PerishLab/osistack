use h3::{Decoder, Encoder, Field, STATIC};

struct Source(u64);

impl Source {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % bound
    }

    fn bytes(&mut self, longest: usize) -> Vec<u8> {
        let length = self.next(longest + 1);
        (0..length).map(|_| self.next(256) as u8).collect()
    }

    fn field(&mut self) -> Field {
        let name = match self.next(3) {
            0 => self.bytes(40),
            _ => STATIC[self.next(STATIC.len())].0.as_bytes().to_vec(),
        };
        let value = match self.next(4) {
            0 => STATIC[self.next(STATIC.len())].1.as_bytes().to_vec(),
            1 => self.bytes(300),
            _ => self.bytes(20),
        };
        Field {
            name,
            value,
            sensitive: self.next(5) == 0,
        }
    }
}

#[test]
fn random() {
    let mut source = Source(7);
    for round in 0..400 {
        let count = source.next(8);
        let fields: Vec<Field> = (0..count).map(|_| source.field()).collect();
        for huffman in [false, true] {
            let block = Encoder::new(huffman).encode(&fields);
            let capacity = source.next(3) * 100;
            let decoded = Decoder::new(capacity).decode(&block);
            assert_eq!(decoded, Ok(fields.clone()), "round {round}");
        }
    }
}

#[test]
fn sensitive() {
    for (index, (name, value)) in STATIC.iter().enumerate() {
        let field = Field::secret(name.as_bytes(), value.as_bytes());
        let block = Encoder::new(false).encode(std::slice::from_ref(&field));
        assert_eq!(block[2] & 0xc0, 0x40, "index {index}");
        assert_eq!(Decoder::new(0).decode(&block), Ok(vec![field]));
    }
}

#[test]
fn matching() {
    let encoder = Encoder::new(false);
    let plain = encoder.encode(&[Field::new(b":path", b"/")]);
    let named = encoder.encode(&[Field::new(b":path", b"/x")]);
    let other = encoder.encode(&[Field::new(b"x-path", b"/")]);
    assert_eq!(plain, [0, 0, 0xc1]);
    assert_eq!(named, [0, 0, 0x51, 0x02, b'/', b'x']);
    assert_eq!(other[2] & 0xe0, 0x20);
}
