use h2::{Codec, Connection, Fault, Frame, Header, Reaction, Setting, Settings};

pub fn settings(list: &[(u16, u32)]) -> Frame {
    let list = list
        .iter()
        .map(|(id, value)| Setting {
            id: *id,
            value: *value,
        })
        .collect();
    Frame::Settings { ack: false, list }
}

pub fn ack() -> Frame {
    Frame::Settings {
        ack: true,
        list: Vec::new(),
    }
}

pub struct Stream(pub u32);

impl Stream {
    pub fn headers(&self, fin: bool) -> Frame {
        Frame::Headers {
            stream: self.0,
            fin,
            complete: true,
            pad: None,
            priority: None,
            block: Vec::new(),
        }
    }

    pub fn data(&self, size: usize, fin: bool) -> Frame {
        Frame::Data {
            stream: self.0,
            fin,
            pad: None,
            data: vec![7; size],
        }
    }

    pub fn window(&self, increment: u32) -> Frame {
        Frame::Window {
            stream: self.0,
            increment,
        }
    }

    pub fn reset(&self) -> Frame {
        Frame::Reset {
            stream: self.0,
            code: 8,
        }
    }
}

pub fn ready(server: &[(u16, u32)]) -> Connection {
    let (mut connection, _) = Connection::start(Settings::default());
    connection.receive(&settings(server)).unwrap();
    connection.receive(&ack()).unwrap();
    connection
}

pub fn feed(connection: &mut Connection, bytes: &[u8]) -> Result<Vec<Reaction>, Fault> {
    let mut reactions = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let codec = connection.inbound();
        let (frame, used) = codec.decode(&bytes[at..]).unwrap().unwrap();
        reactions.push(connection.receive(&frame)?);
        at += used;
    }
    Ok(reactions)
}

pub fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

pub fn fields(pairs: &[(&str, &str)]) -> Vec<Header> {
    let make = |(name, value): &(&str, &str)| Header::new(name.as_bytes(), value.as_bytes());
    pairs.iter().map(make).collect()
}

pub fn wire(codec: &Codec, frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .flat_map(|frame| codec.encode(frame).unwrap())
        .collect()
}

pub fn answered(table: u32) -> Connection {
    let wanted = Settings {
        table,
        ..Settings::default()
    };
    let (mut connection, _) = Connection::start(wanted);
    connection.receive(&settings(&[])).unwrap();
    connection.receive(&ack()).unwrap();
    connection
}

pub fn full(stream: u32, hex: &str, fin: bool) -> Frame {
    Frame::Headers {
        stream,
        fin,
        complete: true,
        pad: None,
        priority: None,
        block: bytes(hex),
    }
}

pub fn opening(stream: u32, hex: &str) -> Frame {
    Frame::Headers {
        stream,
        fin: false,
        complete: false,
        pad: None,
        priority: None,
        block: bytes(hex),
    }
}

pub fn more(stream: u32, hex: &str, complete: bool) -> Frame {
    Frame::Continuation {
        stream,
        complete,
        block: bytes(hex),
    }
}
