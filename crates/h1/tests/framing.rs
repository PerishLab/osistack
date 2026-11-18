use h1::{Error, Framing, Head};

fn head(code: u16, fields: &str) -> Head {
    let text = format!("HTTP/1.1 {code} X\r\n{fields}\r\n");
    Head::parse(text.as_bytes(), 8192).unwrap().unwrap().0
}

fn frame(fields: &str) -> Result<Framing, Error> {
    Framing::of(&head(200, fields))
}

#[test]
fn bodiless() {
    for code in [100, 101, 103, 199, 204, 304] {
        let fields = "Content-Length: 5\r\n";
        assert_eq!(
            Framing::of(&head(code, fields)),
            Ok(Framing::Empty),
            "{code}"
        );
        let fields = "Transfer-Encoding: chunked\r\n";
        assert_eq!(
            Framing::of(&head(code, fields)),
            Ok(Framing::Empty),
            "{code}"
        );
    }
}

#[test]
fn chunked() {
    assert_eq!(
        frame("Transfer-Encoding: chunked\r\n"),
        Ok(Framing::Chunked)
    );
    assert_eq!(
        frame("Transfer-Encoding: CHUNKED\r\n"),
        Ok(Framing::Chunked)
    );
    assert_eq!(
        frame("Transfer-Encoding: gzip, chunked\r\n"),
        Ok(Framing::Chunked)
    );
    assert_eq!(
        frame("Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n"),
        Ok(Framing::Chunked)
    );
}

#[test]
fn close() {
    assert_eq!(frame(""), Ok(Framing::Close));
    assert_eq!(frame("Host: x\r\n"), Ok(Framing::Close));
    assert_eq!(frame("Transfer-Encoding: gzip\r\n"), Ok(Framing::Close));
    assert_eq!(
        frame("Transfer-Encoding: chunked, gzip\r\n"),
        Err(Error::Encoding)
    );
}

#[test]
fn length() {
    assert_eq!(frame("Content-Length: 0\r\n"), Ok(Framing::Length(0)));
    assert_eq!(frame("Content-Length: 1234\r\n"), Ok(Framing::Length(1234)));
    assert_eq!(frame("content-length:  007 \r\n"), Ok(Framing::Length(7)));
    assert_eq!(
        frame("Content-Length: 18446744073709551615\r\n"),
        Ok(Framing::Length(u64::MAX))
    );
}

#[test]
fn merged() {
    assert_eq!(frame("Content-Length: 42, 42\r\n"), Ok(Framing::Length(42)));
    assert_eq!(
        frame("Content-Length: 42\r\nContent-Length: 42\r\n"),
        Ok(Framing::Length(42))
    );
    assert_eq!(
        frame("Content-Length: 42\r\nContent-Length: 42, 42\r\n"),
        Ok(Framing::Length(42))
    );
}

#[test]
fn conflict() {
    assert_eq!(
        frame("Content-Length: 42\r\nContent-Length: 43\r\n"),
        Err(Error::Length)
    );
    assert_eq!(frame("Content-Length: 42, 43\r\n"), Err(Error::Length));
}

#[test]
fn digits() {
    for value in [
        "",
        "+5",
        "-5",
        "5x",
        "0x10",
        "1.5",
        " , ",
        "5,",
        ",5",
        "18446744073709551616",
        "٣",
    ] {
        let fields = format!("Content-Length: {value}\r\n");
        assert_eq!(frame(&fields), Err(Error::Length), "{value:?}");
    }
}

#[test]
fn smuggling() {
    let both = "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n";
    assert_eq!(frame(both), Err(Error::Ambiguous));
    let other = "Transfer-Encoding: gzip\r\nContent-Length: 5\r\n";
    assert_eq!(frame(other), Err(Error::Ambiguous));
}

#[test]
fn encodings() {
    assert_eq!(
        frame("Transfer-Encoding: chunked, chunked\r\n"),
        Err(Error::Encoding)
    );
    assert_eq!(
        frame("Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n"),
        Err(Error::Encoding)
    );
    assert_eq!(frame("Transfer-Encoding:\r\n"), Err(Error::Encoding));
    assert_eq!(frame("Transfer-Encoding: , \r\n"), Err(Error::Encoding));
}
