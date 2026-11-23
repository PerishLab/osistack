use h2::{Codec, Decoder, Encoder, Frame, Header};

#[test]
#[ignore = "timing"]
fn pacing() {
    let headers = [
        Header::new(b":method", b"GET"),
        Header::new(b":path", b"/"),
        Header::new(b":scheme", b"https"),
        Header::new(b"accept", b"text/plain"),
    ];
    let mut encoder = Encoder::new(4096, true);
    let mut decoder = Decoder::new(4096);
    let codec = Codec::default();
    let frame = Frame::Ping {
        ack: false,
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    };
    for _ in 0..256 {
        let block = encoder.encode(&headers);
        assert_eq!(decoder.decode(&block).unwrap(), headers);
        let bytes = codec.encode(&frame).unwrap();
        let (parsed, used) = codec.decode(&bytes).unwrap().unwrap();
        assert_eq!(parsed, frame);
        assert_eq!(used, bytes.len());
    }
}
