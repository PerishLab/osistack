use h1::{Chunked, Error, Field, Head, Version};
use http::{Name, Status, Value};

struct Source(u64);

impl Source {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % bound
    }

    fn token(&mut self, longest: usize) -> String {
        let length = 1 + self.next(longest);
        (0..length)
            .map(|_| b"abcdefghijklmnopqrstuvwxyz012345"[self.next(32)] as char)
            .collect()
    }

    fn reason(&mut self) -> String {
        let words = ["OK", "Created", "Found", "Error", "No Content"];
        words[self.next(words.len())].to_string()
    }

    fn value(&mut self) -> String {
        let length = 1 + self.next(24);
        (0..length)
            .map(|_| b"abcdefghijklmnopqrstuvwxyz012345-/."[self.next(32)] as char)
            .collect()
    }
}

fn write(code: u16, reason: &str, fields: &[Field]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {code} {reason}\r\n").into_bytes();
    for field in fields {
        out.extend_from_slice(field.name.text().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(field.value.bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn field(name: &str, value: &str) -> Field {
    Field {
        name: Name::new(name).unwrap(),
        value: Value::new(value.as_bytes()).unwrap(),
    }
}

#[test]
fn heads() {
    let mut source = Source(19);
    for _ in 0..200 {
        let code = 100 + source.next(500) as u16;
        let reason = source.reason();
        let count = source.next(5);
        let fields: Vec<Field> = (0..count)
            .map(|_| field(&source.token(12), &source.value()))
            .collect();
        let bytes = write(code, &reason, &fields);
        let (head, used) = Head::parse(&bytes, 8192).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(head.version, Version::Http11);
        assert_eq!(head.status, Status::new(code).unwrap());
        assert_eq!(head.reason, reason);
        assert_eq!(head.fields, fields);
        for cut in 0..bytes.len() {
            assert_eq!(Head::parse(&bytes[..cut], 8192), Ok(None), "{cut}");
        }
        assert_eq!(Head::parse(&bytes[..10], 9), Err(Error::Size));
    }
}

#[test]
fn chunks() {
    let mut source = Source(23);
    for _ in 0..200 {
        let length = source.next(80);
        let data: Vec<u8> = (0..length).map(|_| source.next(256) as u8).collect();
        let mut bytes = Chunked::encode(&data);
        bytes.extend(Chunked::finish());
        let body = Chunked::decode(&bytes).unwrap().unwrap();
        assert_eq!(body.data, data);
        assert_eq!(body.used, bytes.len());
        for cut in 0..bytes.len() {
            assert_eq!(Chunked::decode(&bytes[..cut]), Ok(None), "{cut}");
        }
    }
    assert_eq!(Chunked::decode(b"zz\r\n"), Err(Error::Chunk));
}

#[test]
fn hostile() {
    let mut source = Source(29);
    for _ in 0..200 {
        let bytes = write(200, "OK", &[field("server", "osistack")]);
        let mut damaged = bytes.clone();
        let at = source.next(damaged.len());
        damaged[at] = source.next(256) as u8;
        let _ = Head::parse(&damaged, 8192);
        let mut cut = bytes.clone();
        cut.truncate(source.next(bytes.len()));
        let _ = Head::parse(&cut, 4);
    }
}
