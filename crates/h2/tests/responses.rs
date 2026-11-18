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
        hex: "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        headers: &[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
            (":status", "302"),
        ],
        size: 222,
    },
    Block {
        hex: "4803333037c1c0bf",
        headers: &[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            (":status", "307"),
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
        ],
        size: 222,
    },
    Block {
        hex: "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        headers: &[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"),
            ("content-encoding", "gzip"),
            (
                "set-cookie",
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
        ],
        table: &[
            (
                "set-cookie",
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
            ("content-encoding", "gzip"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ],
        size: 215,
    },
];

const HUFFMAN: [Block; 3] = [
    Block {
        hex: "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        headers: &[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
            (":status", "302"),
        ],
        size: 222,
    },
    Block {
        hex: "4883640effc1c0bf",
        headers: &[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            (":status", "307"),
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
        ],
        size: 222,
    },
    Block {
        hex: "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        headers: &[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"),
            ("content-encoding", "gzip"),
            (
                "set-cookie",
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
        ],
        table: &[
            (
                "set-cookie",
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
            ("content-encoding", "gzip"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ],
        size: 215,
    },
];

#[test]
fn plain() {
    run(&PLAIN, 256, false);
}

#[test]
fn huffman() {
    run(&HUFFMAN, 256, true);
}
