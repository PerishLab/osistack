use h2::{Codec, Dependency, Frame, Setting};

struct Source(u64);

impl Source {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % bound
    }

    fn bytes(&mut self, longest: usize) -> Vec<u8> {
        let length = self.next(longest + 1);
        (0..length).map(|_| self.next(256) as u8).collect()
    }

    fn stream(&mut self) -> u32 {
        1 + self.next(0x7fff_fffe) as u32
    }

    fn pad(&mut self) -> Option<u8> {
        (self.next(2) == 0).then(|| self.next(256) as u8)
    }

    fn dependency(&mut self) -> Dependency {
        Dependency {
            exclusive: self.next(2) == 0,
            stream: self.next(0x7fff_ffff) as u32,
            weight: self.next(256) as u8,
        }
    }

    fn frame(&mut self) -> Frame {
        let stream = self.stream();
        match self.next(10) {
            0 => Frame::Data {
                stream,
                fin: self.next(2) == 0,
                pad: self.pad(),
                data: self.bytes(200),
            },
            1 => Frame::Headers {
                stream,
                fin: self.next(2) == 0,
                complete: self.next(2) == 0,
                pad: self.pad(),
                priority: (self.next(2) == 0).then(|| self.dependency()),
                block: self.bytes(100),
            },
            2 => Frame::Priority {
                stream,
                dependency: self.dependency(),
            },
            3 => Frame::Reset {
                stream,
                code: self.next(usize::MAX) as u32,
            },
            4 => self.settings(),
            5 => {
                let data = self.bytes(8);
                let mut eight = [0u8; 8];
                eight[..data.len()].copy_from_slice(&data);
                Frame::Ping {
                    ack: self.next(2) == 0,
                    data: eight,
                }
            }
            6 => Frame::Goaway {
                last: self.next(0x7fff_ffff) as u32,
                code: self.next(usize::MAX) as u32,
                debug: self.bytes(40),
            },
            7 => Frame::Window {
                stream: if self.next(3) == 0 { 0 } else { stream },
                increment: 1 + self.next(0x7fff_fffe) as u32,
            },
            8 => Frame::Continuation {
                stream,
                complete: self.next(2) == 0,
                block: self.bytes(100),
            },
            _ => Frame::Unknown {
                kind: 10 + self.next(246) as u8,
                flags: self.next(256) as u8,
                stream: self.next(0x7fff_ffff) as u32,
                payload: self.bytes(60),
            },
        }
    }

    fn settings(&mut self) -> Frame {
        if self.next(4) == 0 {
            return Frame::Settings {
                ack: true,
                list: Vec::new(),
            };
        }
        let count = self.next(6);
        let list = (0..count)
            .map(|_| match self.next(4) {
                0 => Setting {
                    id: 2,
                    value: self.next(2) as u32,
                },
                1 => Setting {
                    id: 4,
                    value: self.next(0x7fff_ffff) as u32,
                },
                2 => Setting {
                    id: 5,
                    value: 16384 + self.next(0xff_c000) as u32,
                },
                _ => Setting {
                    id: 1 + self.next(3) as u16 * 2 + 6,
                    value: self.next(usize::MAX) as u32,
                },
            })
            .collect();
        Frame::Settings { ack: false, list }
    }
}

fn drain(codec: &Codec, mut bytes: &[u8]) -> Vec<Frame> {
    let mut frames = Vec::new();
    while let Some((frame, used)) = codec.decode(bytes).unwrap() {
        frames.push(frame);
        bytes = &bytes[used..];
    }
    assert!(bytes.is_empty());
    frames
}

#[test]
fn single() {
    let codec = Codec::default();
    let mut source = Source(11);
    for round in 0..2000 {
        let frame = source.frame();
        let bytes = codec.encode(&frame).unwrap();
        let decoded = codec.decode(&bytes);
        assert_eq!(decoded, Ok(Some((frame, bytes.len()))), "round {round}");
    }
}

#[test]
fn joined() {
    let codec = Codec::default();
    let mut source = Source(29);
    for _ in 0..50 {
        let frames: Vec<Frame> = (0..source.next(12)).map(|_| source.frame()).collect();
        let bytes: Vec<u8> = frames
            .iter()
            .flat_map(|frame| codec.encode(frame).unwrap())
            .collect();
        assert_eq!(drain(&codec, &bytes), frames);
    }
}

#[test]
fn trickled() {
    let codec = Codec::default();
    let mut source = Source(43);
    let frames: Vec<Frame> = (0..40).map(|_| source.frame()).collect();
    let bytes: Vec<u8> = frames
        .iter()
        .flat_map(|frame| codec.encode(frame).unwrap())
        .collect();
    let mut pending = Vec::new();
    let mut seen = Vec::new();
    for byte in bytes {
        pending.push(byte);
        while let Some((frame, used)) = codec.decode(&pending).unwrap() {
            seen.push(frame);
            pending.drain(..used);
        }
    }
    assert!(pending.is_empty());
    assert_eq!(seen, frames);
}

#[test]
fn partial() {
    let codec = Codec::default();
    let mut source = Source(5);
    for _ in 0..200 {
        let bytes = codec.encode(&source.frame()).unwrap();
        for cut in 0..bytes.len() {
            assert_eq!(codec.decode(&bytes[..cut]), Ok(None), "cut {cut}");
        }
    }
}

#[test]
fn narrow() {
    let wide = Codec::new(1 << 20).unwrap();
    let frame = Frame::Data {
        stream: 1,
        fin: false,
        pad: None,
        data: vec![9; 100_000],
    };
    let bytes = wide.encode(&frame).unwrap();
    assert_eq!(wide.decode(&bytes), Ok(Some((frame, bytes.len()))));
    assert!(Codec::default().decode(&bytes).is_err());
}
