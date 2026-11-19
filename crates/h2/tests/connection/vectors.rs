pub struct Vector {
    pub hex: &'static str,
    pub fields: &'static [(&'static str, &'static str)],
    pub table: &'static [(&'static str, &'static str)],
    pub size: usize,
}

pub const REQUESTS: [Vector; 3] = [
    Vector {
        hex: "828684410f7777772e6578616d706c652e636f6d",
        fields: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        table: &[(":authority", "www.example.com")],
        size: 57,
    },
    Vector {
        hex: "828684be58086e6f2d6361636865",
        fields: &[
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
    Vector {
        hex: "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        fields: &[
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

pub const RESPONSES: [Vector; 3] = [
    Vector {
        hex: "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        fields: &[
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
    Vector {
        hex: "4803333037c1c0bf",
        fields: &[
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
    Vector {
        hex: "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        fields: &[
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
