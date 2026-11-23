use h2::{Codec, Dependency, Error, Frame, Setting};

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

    fn flag(&mut self) -> bool {
        self.below(2) == 0
    }

    fn stream(&mut self) -> u32 {
        1 + self.below(1024) as u32
    }

    fn bytes(&mut self, limit: usize) -> Vec<u8> {
        let count = self.below(limit);
        (0..count).map(|_| self.next() as u8).collect()
    }

    fn pad(&mut self) -> Option<u8> {
        if self.flag() {
            None
        } else {
            Some(self.below(8) as u8)
        }
    }

    fn dependency(&mut self) -> Dependency {
        Dependency {
            exclusive: self.flag(),
            stream: self.below(1024) as u32,
            weight: self.next() as u8,
        }
    }

    fn setting(&mut self) -> Setting {
        let id = [1u16, 2, 3, 4, 5, 6, 8][self.below(7)];
        let value = match id {
            2 => self.below(2) as u32,
            4 => self.below(1024) as u32,
            5 => 16384 + self.below(1024) as u32,
            _ => self.next() as u32,
        };
        Setting { id, value }
    }

    fn frame(&mut self) -> Frame {
        match self.below(10) {
            0 => Frame::Data {
                stream: self.stream(),
                fin: self.flag(),
                pad: self.pad(),
                data: self.bytes(32),
            },
            1 => Frame::Headers {
                stream: self.stream(),
                fin: self.flag(),
                complete: self.flag(),
                pad: self.pad(),
                priority: if self.flag() {
                    Some(self.dependency())
                } else {
                    None
                },
                block: self.bytes(32),
            },
            2 => Frame::Priority {
                stream: self.stream(),
                dependency: self.dependency(),
            },
            3 => Frame::Reset {
                stream: self.stream(),
                code: self.next() as u32,
            },
            4 => {
                let ack = self.flag();
                Frame::Settings {
                    ack,
                    list: if ack {
                        Vec::new()
                    } else {
                        (0..self.below(4)).map(|_| self.setting()).collect()
                    },
                }
            }
            5 => Frame::Ping {
                ack: self.flag(),
                data: self.next().to_be_bytes(),
            },
            6 => Frame::Goaway {
                last: self.below(1024) as u32,
                code: self.next() as u32,
                debug: self.bytes(16),
            },
            7 => Frame::Window {
                stream: if self.flag() { 0 } else { self.stream() },
                increment: 1 + self.below(1024) as u32,
            },
            8 => Frame::Continuation {
                stream: self.stream(),
                complete: self.flag(),
                block: self.bytes(32),
            },
            _ => Frame::Unknown {
                kind: 10 + self.below(246) as u8,
                flags: self.next() as u8,
                stream: if self.flag() { 0 } else { self.stream() },
                payload: self.bytes(16),
            },
        }
    }
}

fn wire(frame: &Frame) -> Vec<u8> {
    Codec::default().encode(frame).unwrap()
}

fn read(bytes: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
    Codec::default().decode(bytes)
}

#[test]
fn frames() {
    let mut dice = Dice::new(23);
    for _ in 0..800 {
        let frame = dice.frame();
        let bytes = wire(&frame);
        assert_eq!(read(&bytes), Ok(Some((frame, bytes.len()))));
    }
}

#[test]
fn prefixes() {
    let mut dice = Dice::new(29);
    for _ in 0..400 {
        let bytes = wire(&dice.frame());
        for at in 0..bytes.len() {
            assert_eq!(read(&bytes[..at]), Ok(None), "{at} of {}", bytes.len());
        }
    }
}

#[test]
fn malformed() {
    fn frame(kind: u8, flags: u8, stream: u8, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut bytes = length.to_be_bytes()[1..].to_vec();
        bytes.extend([kind, flags, 0, 0, 0, stream]);
        bytes.extend(payload);
        bytes
    }

    assert_eq!(read(&frame(0, 0, 0, b"x")), Err(Error::Stream));
    assert_eq!(read(&frame(4, 0, 1, &[])), Err(Error::Stream));
    assert_eq!(read(&frame(6, 0, 0, &[0; 7])), Err(Error::Length));
    assert_eq!(read(&frame(8, 0, 1, &[0, 0, 0, 0])), Err(Error::Increment));
    assert_eq!(read(&frame(5, 0, 1, &[0; 4])), Err(Error::Push));
    assert_eq!(read(&frame(4, 1, 0, &[0; 6])), Err(Error::Length));
    assert_eq!(
        read(&frame(4, 0, 0, &[0, 2, 0, 0, 0, 2])),
        Err(Error::Setting)
    );
    assert_eq!(read(&frame(0, 8, 1, &[10])), Err(Error::Padding));
    let huge = {
        let mut bytes = [0u8; 9];
        bytes[0] = 0x40;
        bytes[3] = 0;
        bytes[8] = 1;
        bytes
    };
    assert_eq!(read(&huge), Err(Error::Length));
}
