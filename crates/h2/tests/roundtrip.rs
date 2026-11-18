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

fn run(limit: usize, huffman: bool, seed: u64) {
    let mut source = Source(seed);
    let mut decoder = Decoder::new(limit);
    let mut encoder = Encoder::new(limit, huffman);
    decoder.decode(&encoder.encode(&[])).unwrap();
    for round in 0..200 {
        if round % 17 == 5 {
            encoder.resize(source.next(limit + 1));
        }
        let count = source.next(8);
        let headers: Vec<Header> = (0..count).map(|_| source.header()).collect();
        let block = encoder.encode(&headers);
        assert_eq!(decoder.decode(&block).unwrap(), headers, "{round}");
        assert_eq!(decoder.size(), encoder.size(), "{round}");
        assert_eq!(decoder.dynamic(), encoder.dynamic(), "{round}");
    }
}

#[test]
fn plain() {
    for limit in [0, 40, 300, 4096] {
        run(limit, false, limit as u64 + 1);
    }
}

#[test]
fn huffman() {
    for limit in [0, 40, 300, 4096] {
        run(limit, true, limit as u64 + 77);
    }
}

#[test]
fn shrinking() {
    let mut encoder = Encoder::new(4096, true);
    let mut decoder = Decoder::new(4096);
    let list = [
        Header::new(b"alpha", b"one"),
        Header::new(b"beta", b"two"),
        Header::secret(b"key", b"hidden"),
    ];
    decoder.decode(&encoder.encode(&list)).unwrap();
    assert_eq!(decoder.dynamic().len(), 2);
    encoder.resize(40);
    decoder.decode(&encoder.encode(&list)).unwrap();
    assert_eq!(decoder.dynamic(), encoder.dynamic());
    assert!(decoder.size() <= 40);
}
