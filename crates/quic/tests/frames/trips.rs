use crate::support::*;
use quic::{Direction, Ecn, Frame};

impl Dice {
    fn number(&mut self) -> u64 {
        let width = [6, 14, 30, 62][self.below(4)];
        self.next() >> (64 - width)
    }

    fn kind(&mut self) -> Direction {
        [Direction::Bidi, Direction::Uni][self.below(2)]
    }

    fn data(&mut self) -> Vec<u8> {
        self.upto(40)
    }

    fn acked(&mut self) -> Frame {
        let largest = 10_000 + self.number() % 1_000_000;
        let count = self.below(5);
        let ranges = (0..count)
            .map(|_| (self.next() % 20, self.next() % 20))
            .collect::<Vec<_>>();
        let first = self.next() % 100;
        let mut found = ack(largest, self.number(), first, &ranges);
        if self.below(2) == 0 {
            found.ecn = Some(Ecn {
                ect0: self.number(),
                ect1: self.number(),
                ce: self.number(),
            });
        }
        Frame::Ack(found)
    }

    fn pick(&mut self, sized: bool) -> Frame {
        let offset = if self.below(2) == 0 {
            0
        } else {
            self.number() >> 2
        };
        match self.below(19) {
            0 => Frame::Padding(1 + self.below(30)),
            1 => Frame::Ping,
            2 => self.acked(),
            3 => Frame::Reset {
                stream: self.number(),
                code: self.number(),
                size: self.number(),
            },
            4 => Frame::Stop {
                stream: self.number(),
                code: self.number(),
            },
            5 => Frame::Crypto {
                offset,
                data: self.data(),
            },
            6 => Frame::Token(self.span(1, 30)),
            7 => stream(
                self.number(),
                offset,
                &self.data(),
                (self.below(2) == 0, sized),
            ),
            8 => Frame::Data(self.number()),
            9 => Frame::Window {
                stream: self.number(),
                limit: self.number(),
            },
            10 => Frame::Streams {
                kind: self.kind(),
                limit: self.number() >> 3,
            },
            11 => Frame::Blocked(self.number()),
            12 => Frame::Stalled {
                stream: self.number(),
                limit: self.number(),
            },
            13 => Frame::Choked {
                kind: self.kind(),
                limit: self.number() >> 3,
            },
            14 => self.issue(),
            15 => Frame::Retire(self.number()),
            16 => self.closing(),
            17 => Frame::Challenge(self.bytes(8).try_into().unwrap()),
            _ => Frame::Done,
        }
    }

    fn issue(&mut self) -> Frame {
        let sequence = self.number();
        Frame::Issue {
            sequence,
            retire: sequence / 2,
            cid: self.span(1, 20),
            token: self.bytes(16).try_into().unwrap(),
        }
    }

    fn closing(&mut self) -> Frame {
        if self.below(2) == 0 {
            return Frame::Transport {
                code: self.number(),
                frame: self.number(),
                reason: self.data(),
            };
        }
        Frame::Application {
            code: self.number(),
            reason: self.data(),
        }
    }

    fn sequence(&mut self) -> Vec<Frame> {
        let mut frames: Vec<Frame> = Vec::new();
        for _ in 0..1 + self.below(8) {
            let frame = self.pick(true);
            let twin = matches!(frame, Frame::Padding(_))
                && matches!(frames.last(), Some(Frame::Padding(_)));
            if !twin {
                frames.push(frame);
            }
        }
        if self.below(3) == 0 {
            frames.push(stream(
                self.number(),
                self.number() >> 2,
                &self.data(),
                (false, false),
            ));
        }
        frames
    }
}

#[test]
fn trips() {
    let mut dice = Dice::new(7);
    for _ in 0..300 {
        let frames = dice.sequence();
        let bytes = Frame::join(&frames).unwrap();
        assert_eq!(Frame::all(&bytes).unwrap(), frames);
        for frame in &frames {
            let bytes = frame.write().unwrap();
            assert_eq!(Frame::parse(&bytes).unwrap().1, bytes.len());
        }
    }
}

#[test]
fn damaged() {
    let mut dice = Dice::new(11);
    let mut kept = 0;
    for _ in 0..600 {
        let frames = dice.sequence();
        let mut bytes = Frame::join(&frames).unwrap();
        let at = dice.below(bytes.len());
        bytes[at] = dice.next() as u8;
        let cut = dice.below(bytes.len() + 1);
        match Frame::all(&bytes[..cut]) {
            Err(_) => {}
            Ok(found) => {
                kept += 1;
                let again = Frame::join(&found).unwrap();
                assert_eq!(Frame::all(&again).unwrap(), found);
            }
        }
    }
    assert!(kept > 50);
}

#[test]
fn noise() {
    let mut dice = Dice::new(13);
    for _ in 0..2000 {
        let bytes = dice.upto(60);
        if let Ok(found) = Frame::all(&bytes) {
            let again = Frame::join(&found).unwrap();
            assert_eq!(Frame::all(&again).unwrap(), found);
        }
    }
}
