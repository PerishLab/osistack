use h3::{Decoder, Encoder, Field, STATIC};

#[test]
fn count() {
    assert_eq!(STATIC.len(), 99);
}

#[test]
fn entries() {
    let pinned: [(usize, &str, &str); 24] = [
        (0, ":authority", ""),
        (1, ":path", "/"),
        (2, "age", "0"),
        (4, "content-length", "0"),
        (15, ":method", "CONNECT"),
        (17, ":method", "GET"),
        (23, ":scheme", "https"),
        (25, ":status", "200"),
        (30, "accept", "application/dns-message"),
        (41, "cache-control", "public, max-age=31536000"),
        (44, "content-type", "application/dns-message"),
        (45, "content-type", "application/javascript"),
        (46, "content-type", "application/json"),
        (47, "content-type", "application/x-www-form-urlencoded"),
        (52, "content-type", "text/html; charset=utf-8"),
        (54, "content-type", "text/plain;charset=utf-8"),
        (
            57,
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        ),
        (
            58,
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ),
        (
            85,
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
        (92, "server", ""),
        (93, "timing-allow-origin", "*"),
        (96, "x-forwarded-for", ""),
        (97, "x-frame-options", "deny"),
        (98, "x-frame-options", "sameorigin"),
    ];
    for (index, name, value) in pinned {
        assert_eq!(STATIC[index], (name, value));
    }
}

#[test]
fn indexed() {
    let encoder = Encoder::new(false);
    let decoder = Decoder::new(0);
    for (index, (name, value)) in STATIC.iter().enumerate() {
        let field = Field::new(name.as_bytes(), value.as_bytes());
        let block = encoder.encode(std::slice::from_ref(&field));
        let size = if index < 63 { 3 } else { 4 };
        assert_eq!(block.len(), size, "index {index}");
        assert_eq!(&block[..2], &[0, 0]);
        assert_eq!(block[2] & 0xc0, 0xc0);
        assert_eq!(decoder.decode(&block).unwrap(), vec![field]);
    }
}

#[test]
fn unique() {
    for (left, one) in STATIC.iter().enumerate() {
        for other in &STATIC[left + 1..] {
            assert_ne!(one, other);
        }
    }
}
