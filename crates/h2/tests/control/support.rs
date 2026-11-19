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
            block: vec![0x82],
        }
    }

    pub fn block(&self, bytes: &[u8]) -> Frame {
        Frame::Headers {
            stream: self.0,
            fin: false,
            complete: true,
            pad: None,
            priority: None,
            block: bytes.to_vec(),
        }
    }

    pub fn data(&self, size: usize) -> Frame {
        Frame::Data {
            stream: self.0,
            fin: false,
            pad: None,
            data: vec![7; size],
        }
    }

    pub fn reset(&self, code: u32) -> Frame {
        Frame::Reset {
            stream: self.0,
            code,
        }
    }
}

pub fn ready(server: &[(u16, u32)]) -> Connection {
    let (mut connection, _) = Connection::start(Settings::default());
    connection.receive(&settings(server)).unwrap();
    connection.receive(&ack()).unwrap();
    connection
}

pub fn opened(connection: &mut Connection, streams: &[(u32, bool)]) {
    for (stream, fin) in streams {
        connection.send(&Stream(*stream).headers(*fin)).unwrap();
    }
}

pub fn feed(connection: &mut Connection, frames: &[Frame]) -> Result<Vec<Reaction>, Fault> {
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend(Codec::default().encode(frame).unwrap());
    }
    let mut reactions = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let (frame, used) = connection.inbound().decode(&bytes[at..]).unwrap().unwrap();
        reactions.push(connection.receive(&frame)?);
        at += used;
    }
    Ok(reactions)
}

pub fn pair(name: &str, value: &str) -> Header {
    Header::new(name.as_bytes(), value.as_bytes())
}
