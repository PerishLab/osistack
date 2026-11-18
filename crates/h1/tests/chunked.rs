use h1::{Body, Chunked, Error};

fn decode(text: &str) -> Result<Option<Body>, Error> {
    Chunked::decode(text.as_bytes())
}

fn body(data: &str, used: usize) -> Result<Option<Body>, Error> {
    Ok(Some(Body {
        data: data.as_bytes().to_vec(),
        used,
    }))
}

#[test]
fn single() {
    let text = "5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(decode(text), body("hello", text.len()));
}

#[test]
fn several() {
    let text = "5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n";
    assert_eq!(decode(text), body("hello world", text.len()));
}

#[test]
fn empty() {
    assert_eq!(decode("0\r\n\r\n"), body("", 5));
}

#[test]
fn consumed() {
    let text = "3\r\nabc\r\n0\r\n\r\nNEXT";
    assert_eq!(decode(text), body("abc", text.len() - 4));
}

#[test]
fn hexadecimal() {
    let data = "x".repeat(26);
    let text = format!("1A\r\n{data}\r\n1a\r\n{data}\r\n00\r\n\r\n");
    let expected = data.repeat(2);
    assert_eq!(decode(&text), body(&expected, text.len()));
}

#[test]
fn extensions() {
    assert_eq!(
        decode("3;name=value\r\nabc\r\n0;last\r\n\r\n"),
        body("abc", 29)
    );
    assert_eq!(
        decode("3;a=\"x y\";\tb\r\nabc\r\n0\r\n\r\n"),
        body("abc", 24)
    );
    assert_eq!(decode("3;\u{1}\r\nabc\r\n0\r\n\r\n"), Err(Error::Chunk));
    assert_eq!(decode("3;a\u{7f}\r\nabc\r\n0\r\n\r\n"), Err(Error::Chunk));
    assert_eq!(decode("0;\u{0}\r\n\r\n"), Err(Error::Chunk));
}

#[test]
fn incomplete() {
    let text = "5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
    for cut in 0..text.len() {
        assert_eq!(decode(&text[..cut]), Ok(None), "{cut}");
    }
    assert!(decode(text).unwrap().is_some());
}

#[test]
fn newline() {
    assert_eq!(decode("5\nhello\r\n0\r\n\r\n"), Err(Error::Chunk));
    assert_eq!(decode("5\r\nhello\n0\r\n\r\n"), Err(Error::Chunk));
    assert_eq!(decode("5\r\nhelloXX0\r\n\r\n"), Err(Error::Chunk));
    assert_eq!(decode("5\r\nhello\r\n0\r\n\n"), Err(Error::Trailer));
}

#[test]
fn digits() {
    for text in [
        "\r\nabc\r\n",
        "g\r\n",
        "-1\r\n",
        "+1\r\n",
        " 3\r\nabc\r\n",
        "3 \r\nabc\r\n",
        "0x3\r\nabc\r\n",
    ] {
        assert_eq!(decode(text), Err(Error::Chunk), "{text:?}");
    }
}

#[test]
fn overflow() {
    assert_eq!(decode("10000000000000000\r\n"), Err(Error::Size));
    assert_eq!(decode("FFFFFFFFFFFFFFFFF\r\n"), Err(Error::Size));
    assert_eq!(decode("FFFFFFFFFFFFFFFF\r\nabc"), Err(Error::Size));
    assert_eq!(decode("FFFFFF\r\nabc"), Ok(None));
    assert_eq!(
        decode("0000000000000000000000000000005\r\nhello\r\n0\r\n\r\n"),
        body("hello", 45)
    );
}

#[test]
fn trailers() {
    assert_eq!(
        decode("3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n"),
        Err(Error::Trailer)
    );
    assert_eq!(decode("0\r\nX\r\n\r\n"), Err(Error::Trailer));
}
