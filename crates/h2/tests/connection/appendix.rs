use crate::support::*;
use crate::vectors::{REQUESTS, RESPONSES, Vector};
use h2::{Block, Frame};

#[derive(Clone, Copy, Debug)]
enum Style {
    Whole,
    Halves,
    Bytes,
}

impl Style {
    fn frames(self, stream: u32, block: &[u8]) -> Vec<Frame> {
        let cut = match self {
            Style::Whole => block.len(),
            Style::Halves => block.len() / 2,
            Style::Bytes => 1,
        };
        let (head, tail) = block.split_at(cut);
        let mut frames = vec![Frame::Headers {
            stream,
            fin: true,
            complete: tail.is_empty(),
            pad: None,
            priority: None,
            block: head.to_vec(),
        }];
        let pieces: Vec<&[u8]> = match self {
            Style::Bytes => tail.chunks(1).collect(),
            _ => vec![tail],
        };
        for piece in pieces.iter().filter(|piece| !piece.is_empty()) {
            frames.push(Frame::Continuation {
                stream,
                complete: false,
                block: piece.to_vec(),
            });
        }
        if let Some(Frame::Continuation { complete, .. }) = frames.last_mut() {
            *complete = true;
        }
        frames
    }
}

fn drive(vectors: &[Vector], table: u32, style: Style) {
    let mut connection = answered(table);
    for (at, vector) in vectors.iter().enumerate() {
        let stream = 2 * at as u32 + 1;
        connection.send(&Stream(stream).headers(true)).unwrap();
        let frames = style.frames(stream, &bytes(vector.hex));
        let codec = connection.inbound();
        let reactions = feed(&mut connection, &wire(&codec, &frames)).unwrap();
        let last = reactions.last().unwrap();
        let expected = Block {
            stream,
            fields: fields(vector.fields),
            fin: true,
        };
        assert_eq!(last.block, Some(expected), "{style:?} {at}");
        let pending = &reactions[..reactions.len() - 1];
        assert!(pending.iter().all(|reaction| reaction.block.is_none()));
        assert_eq!(connection.decoder().size(), vector.size, "{style:?} {at}");
        let table = fields(vector.table);
        assert_eq!(connection.decoder().dynamic(), table, "{style:?} {at}");
    }
}

#[test]
fn requests() {
    for style in [Style::Whole, Style::Halves, Style::Bytes] {
        drive(&REQUESTS, 4096, style);
    }
}

#[test]
fn responses() {
    for style in [Style::Whole, Style::Halves, Style::Bytes] {
        drive(&RESPONSES, 256, style);
    }
}

#[test]
fn exchange() {
    let key = ("x-key", "value");
    let big = "a".repeat(100_000);
    let list = fields(&[(":method", "GET"), ("x-big", &big), key]);
    let mut sender = ready(&[]);
    let mut peer = ready(&[]);
    for stream in [1u32, 3] {
        let frames = sender.headers(stream, &list, true).unwrap();
        assert!(frames.len() > 2);
        peer.send(&Stream(stream).headers(false)).unwrap();
        let bytes = wire(&sender.outbound(), &frames);
        let reactions = feed(&mut peer, &bytes).unwrap();
        assert_eq!(reactions.len(), frames.len());
        let expected = Block {
            stream,
            fields: list.clone(),
            fin: true,
        };
        assert_eq!(reactions.last().unwrap().block, Some(expected));
        assert_eq!(peer.decoder().dynamic(), sender.encoder().dynamic());
        assert_eq!(peer.decoder().dynamic(), fields(&[key]));
    }
}
