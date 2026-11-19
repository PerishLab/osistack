use h2::{Decoder, Encoder, Header};

struct Block {
    hex: &'static str,
    headers: &'static [(&'static str, &'static str)],
    table: &'static [(&'static str, &'static str)],
    size: usize,
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

fn list(pairs: &[(&str, &str)]) -> Vec<Header> {
    let make = |(name, value): &(&str, &str)| Header::new(name.as_bytes(), value.as_bytes());
    pairs.iter().map(make).collect()
}

fn run(blocks: &[Block], limit: usize, huffman: bool) {
    let mut decoder = Decoder::new(limit);
    let mut encoder = Encoder::new(limit, huffman);
    for (at, block) in blocks.iter().enumerate() {
        let headers = list(block.headers);
        assert_eq!(
            decoder.decode(&bytes(block.hex)).unwrap(),
            headers,
            "decode {at}"
        );
        assert_eq!(encoder.encode(&headers), bytes(block.hex), "encode {at}");
        for (name, size, table) in [
            ("decoder", decoder.size(), decoder.dynamic()),
            ("encoder", encoder.size(), encoder.dynamic()),
        ] {
            assert_eq!(size, block.size, "{name} size {at}");
            assert_eq!(table, list(block.table), "{name} table {at}");
        }
    }
}

const PLAIN: [Block; 3] = [
    Block {
        hex: "828684410f7777772e6578616d706c652e636f6d",
        headers: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        table: &[(":authority", "www.example.com")],
        size: 57,
    },
    Block {
        hex: "828684be58086e6f2d6361636865",
        headers: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ],
        table: &[
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        size: 110,
    },
    Block {
        hex: "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        headers: &[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ],
        table: &[
            ("custom-key", "custom-value"),
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        size: 164,
    },
];

const HUFFMAN: [Block; 3] = [
    Block {
        hex: "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        headers: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        table: &[(":authority", "www.example.com")],
        size: 57,
    },
    Block {
        hex: "828684be5886a8eb10649cbf",
        headers: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ],
        table: &[
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        size: 110,
    },
    Block {
        hex: "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        headers: &[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ],
        table: &[
            ("custom-key", "custom-value"),
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        size: 164,
    },
];

#[test]
fn plain() {
    run(&PLAIN, 4096, false);
}

#[test]
fn huffman() {
    run(&HUFFMAN, 4096, true);
}
