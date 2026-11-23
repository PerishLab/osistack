use h2::{Decoder, Encoder, Header};

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

    fn header(&mut self) -> Header {
        let names: [&[u8]; 6] = [
            b":authority",
            b"cookie",
            b"accept",
            b":method",
            b"x-custom",
            b"content-type",
        ];
        let name = match self.next(3) {
            0 => self.bytes(12),
            _ => names[self.next(names.len())].to_vec(),
        };
        let value = match self.next(4) {
            0 => b"GET".to_vec(),
            1 => self.bytes(300),
            _ => self.bytes(20),
        };
        Header {
            name,
            value,
            sensitive: self.next(5) == 0,
        }
    }
}

#[test]
fn prefixes() {
    let mut source = Source(19);
    let mut refused = 0;
    for _ in 0..200 {
        let huffman = source.next(2) == 0;
        let mut encoder = Encoder::new(4096, huffman);
        let count = 1 + source.next(6);
        let headers: Vec<Header> = (0..count).map(|_| source.header()).collect();
        let block = encoder.encode(&headers);
        assert_eq!(Decoder::new(4096).decode(&block).unwrap(), headers);
        for cut in 0..block.len() {
            if Decoder::new(4096).decode(&block[..cut]).is_err() {
                refused += 1;
            }
        }
    }
    assert!(refused > 0);
}
