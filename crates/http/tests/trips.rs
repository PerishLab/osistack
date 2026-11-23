use http::{Class, Error, Method, Name, Status, Value};

const TOKEN: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~";

struct Dice(u64);

impl Dice {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn token(&mut self) -> String {
        let count = 1 + self.below(24);
        (0..count)
            .map(|_| TOKEN[self.below(TOKEN.len())] as char)
            .collect()
    }

    fn dirty(&mut self) -> String {
        let mut text = self.token();
        let bad = [b' ', b':', b'/', b'@', 0, b'\r', b'\n', 0x80][self.below(8)];
        let at = self.below(text.len() + 1);
        text.insert(at, bad as char);
        text
    }

    fn value(&mut self) -> Vec<u8> {
        let count = self.below(40);
        let mut bytes: Vec<u8> = (0..count)
            .map(|_| {
                let code = (self.next() % 223) as u8;
                if code < 95 { code + 0x20 } else { code + 0x21 }
            })
            .collect();
        while bytes.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            bytes.remove(0);
        }
        while bytes.last().is_some_and(|b| *b == b' ' || *b == b'\t') {
            bytes.pop();
        }
        bytes
    }
}

fn classed(code: u16) -> Class {
    [
        Class::Informational,
        Class::Success,
        Class::Redirection,
        Class::Client,
        Class::Server,
    ][(code / 100 - 1) as usize]
}

#[test]
fn methods() {
    let mut dice = Dice::new(3);
    for _ in 0..800 {
        let text = dice.token();
        assert_eq!(Method::new(&text).unwrap().text(), text);
    }
}

#[test]
fn statuses() {
    for code in 100..=599 {
        let status = Status::new(code).unwrap();
        assert_eq!(status.get(), code);
        assert_eq!(status.class(), classed(code));
    }
}

#[test]
fn names() {
    let mut dice = Dice::new(7);
    for _ in 0..800 {
        let text = dice.token();
        let name = Name::new(&text).unwrap();
        assert_eq!(name.text(), text.to_ascii_lowercase());
        assert_eq!(name, Name::new(&text.to_ascii_uppercase()).unwrap());
    }
}

#[test]
fn values() {
    let mut dice = Dice::new(11);
    for _ in 0..800 {
        let bytes = dice.value();
        assert_eq!(Value::new(&bytes).unwrap().bytes(), bytes);
    }
}

#[test]
fn refused() {
    let mut dice = Dice::new(13);
    for _ in 0..400 {
        let text = dice.dirty();
        assert_eq!(Method::new(&text), Err(Error::Character), "{text:?}");
        assert_eq!(Name::new(&text), Err(Error::Character), "{text:?}");
        let code = [0, 99, 600, 999, u16::MAX][dice.below(5)];
        assert_eq!(Status::new(code), Err(Error::Range), "{code}");
        let mut bytes = dice.value();
        if bytes.is_empty() {
            bytes.push(b'x');
        }
        let at = dice.below(bytes.len());
        bytes[at] = [0, 1, 0x1f, 0x7f, b'\r', b'\n'][dice.below(6)];
        assert_eq!(Value::new(&bytes), Err(Error::Character), "{bytes:?}");
        let pad = [b' ', b'\t'][dice.below(2)];
        let mut padded = dice.value();
        if dice.below(2) == 0 {
            padded.insert(0, pad);
        } else {
            padded.push(pad);
        }
        assert_eq!(Value::new(&padded), Err(Error::Padding), "{padded:?}");
    }
}
