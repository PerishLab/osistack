use h2::{Connection, Fault, Frame, Reaction, Setting, Settings};

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
