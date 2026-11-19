use h3::{Alternative, Defect, Directive, Origin};
use std::net::Ipv6Addr;

pub struct Dice(u64);

impl Dice {
    pub fn new(seed: u64) -> Dice {
        Dice(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }
}

pub fn origin() -> Origin {
    Origin::new("www.example.com", 443)
}

pub fn parse(text: &str) -> Result<Directive, Defect> {
    Directive::parse(text, &origin())
}

pub fn offer(text: &str) -> Vec<Alternative> {
    match parse(text) {
        Ok(Directive::Offer(list)) => list,
        other => panic!("{text}: {other:?}"),
    }
}

pub fn one(text: &str) -> Alternative {
    let mut list = offer(text);
    assert_eq!(list.len(), 1, "{text}");
    list.remove(0)
}

pub fn alt(protocol: &str, host: &str, port: u16, age: u64) -> Alternative {
    Alternative {
        protocol: protocol.as_bytes().to_vec(),
        host: host.to_string(),
        port,
        age,
        persist: false,
    }
}

pub fn keep(mut alt: Alternative) -> Alternative {
    alt.persist = true;
    alt
}

pub struct Made {
    pub text: String,
    pub alts: Vec<Alternative>,
}

fn plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$&'*+-.^_`|~".contains(&byte)
}

fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        if plain(*byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Dice {
    fn space(&mut self) -> String {
        (0..self.below(3))
            .map(|_| if self.below(2) == 0 { ' ' } else { '\t' })
            .collect()
    }

    fn quote(&mut self, content: &str) -> String {
        let mut out = String::from("\"");
        for ch in content.chars() {
            if ch == '"' || ch == '\\' || self.below(5) == 0 {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('"');
        out
    }

    fn protocol(&mut self) -> Vec<u8> {
        match self.below(3) {
            0 => b"h3".to_vec(),
            1 => (0..1 + self.below(5))
                .map(|_| b"abcxyz019-"[self.below(10)])
                .collect(),
            _ => (0..1 + self.below(4)).map(|_| self.next() as u8).collect(),
        }
    }

    fn labels(&mut self) -> (String, String) {
        let mut written = Vec::new();
        for _ in 0..1 + self.below(3) {
            let size = 1 + self.below(9);
            written.push(
                (0..size)
                    .map(|_| b"abcdefghij0123456789"[self.below(20)] as char)
                    .collect::<String>(),
            );
        }
        written.push(format!("t{}", self.below(100)));
        let lower = written.join(".");
        let shown = if self.below(2) == 0 {
            lower.to_ascii_uppercase()
        } else {
            lower.clone()
        };
        (shown, lower)
    }

    fn host(&mut self, home: &Origin) -> (String, String) {
        match self.below(4) {
            0 => (String::new(), home.host.clone()),
            1 => self.labels(),
            2 => {
                let text = format!(
                    "{}.{}.{}.{}",
                    self.below(256),
                    self.below(256),
                    self.below(256),
                    self.below(256)
                );
                (text.clone(), text)
            }
            _ => {
                let groups: Vec<u16> = (0..8).map(|_| self.next() as u16).collect();
                let shown: Vec<String> = groups.iter().map(|group| format!("{group:x}")).collect();
                let canon = Ipv6Addr::new(
                    groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6],
                    groups[7],
                );
                (format!("[{}]", shown.join(":")), canon.to_string())
            }
        }
    }

    fn extras(&mut self, age: Option<u64>, persist: Option<usize>) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(value) = age {
            let shown = if self.below(2) == 0 {
                format!("\"{value}\"")
            } else {
                value.to_string()
            };
            out.push(format!("ma={shown}"));
        }
        if let Some(pick) = persist {
            let text = ["1", "0", "2", "true"][pick];
            let shown = if text == "1" && self.below(2) == 0 {
                "\"1\"".to_string()
            } else {
                text.to_string()
            };
            out.push(format!("persist={shown}"));
        }
        for _ in 0..self.below(3) {
            let name = ["foo", "x-y", "Ma", "MA", "Persist"][self.below(5)];
            let value = if self.below(2) == 0 {
                "v1".to_string()
            } else {
                self.quote("a,b;c\"d")
            };
            out.push(format!("{name}={value}"));
        }
        out
    }

    fn item(&mut self, home: &Origin, ceiling: u64) -> (String, Alternative) {
        let proto = self.protocol();
        let (written, expected) = self.host(home);
        let port = 1 + self.below(65535) as u16;
        let zeros = "0".repeat(self.below(3));
        let auth = self.quote(&format!("{written}:{zeros}{port}"));
        let age = (self.below(2) == 0).then(|| self.next() % ceiling);
        let persist = (self.below(2) == 0).then(|| self.below(4));
        let mut params = self.extras(age, persist);
        for at in (1..params.len()).rev() {
            params.swap(at, self.below(at + 1));
        }
        let mut text = format!("{}={}", escape(&proto), auth);
        for param in params {
            text.push_str(&format!("{}; {}", self.space(), param));
        }
        let alt = Alternative {
            protocol: proto,
            host: expected,
            port,
            age: age.map_or(86400, |value| value.min(1 << 31)),
            persist: persist == Some(0),
        };
        (text, alt)
    }

    pub fn build(&mut self, home: &Origin, ceiling: u64) -> Made {
        let count = 1 + self.below(4);
        let mut text = self.space();
        let mut alts = Vec::new();
        for at in 0..count {
            let (shown, alt) = self.item(home, ceiling);
            text.push_str(&shown);
            alts.push(alt);
            text.push_str(&self.space());
            let commas = if at + 1 == count {
                self.below(2)
            } else {
                1 + self.below(2)
            };
            text.push_str(&",".repeat(commas));
            text.push_str(&self.space());
        }
        Made { text, alts }
    }
}
