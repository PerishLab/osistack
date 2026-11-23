use quic::{
    Ack, Arrival, Control, Flight, Frame, Header, Initial, Kind, Mark, Mode, Seen, Sent, Space,
};

fn arrival(number: u64, time: u64) -> Arrival {
    Arrival {
        number,
        time,
        eliciting: true,
        mark: Mark::Plain,
    }
}

fn sent(number: u64, time: u64) -> Sent {
    Sent {
        number,
        time,
        size: 1200,
        eliciting: true,
        flight: true,
    }
}

fn ack(largest: u64, first: u64) -> Ack {
    Ack {
        largest,
        delay: 0,
        first,
        ranges: Vec::new(),
        ecn: None,
    }
}

#[test]
fn closes() {
    let original = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let client = [9u8; 4];
    let server = [4u8; 8];
    let mut control = Control::new(25_000, 3);
    assert_eq!(
        control.ingest(Space::Handshake, arrival(0, 700)),
        Seen::Fresh
    );
    assert_eq!(
        control.ingest(Space::Handshake, arrival(1, 800)),
        Seen::Fresh
    );
    let found = control.ack(Space::Handshake, 800).unwrap();
    assert_eq!((found.largest, found.first), (1, 1));
    let keys = Initial::new(&original).unwrap();
    let space = Flight {
        kind: Kind::Initial,
        dcid: server.to_vec(),
        scid: client.to_vec(),
        token: Vec::new(),
    };
    let payload = Frame::Ack(found).write().unwrap();
    let packet = space.write(&keys.client, 0, &payload).unwrap();
    let Header::Long(long) = Header::parse(&packet, server.len()).unwrap() else {
        panic!("not long");
    };
    let opened = keys.client.unprotect(&packet, long.offset, None).unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    let Frame::Ack(back) = &frames[0] else {
        panic!("not ack");
    };
    assert_eq!((back.largest, back.first), (1, 1));
    control.sent(Space::Handshake, sent(0, 100));
    let out = control.acked(200, Space::Handshake, &ack(0, 0)).unwrap();
    assert_eq!(out.acked.len(), 1);
    assert!(out.lost.is_empty());
    let frame = control.close(300, 0, 0, b"done").unwrap();
    assert_eq!(control.life.mode(), Mode::Closing);
    let payload = frame.write().unwrap();
    let packet = space.write(&keys.client, 1, &payload).unwrap();
    let Header::Long(long) = Header::parse(&packet, server.len()).unwrap() else {
        panic!("not long");
    };
    let opened = keys.client.unprotect(&packet, long.offset, None).unwrap();
    let frames = Frame::all(&opened.payload).unwrap();
    assert_eq!(frames[0], frame);
    assert!(control.life.expire(300 + 3_000));
    assert_eq!(control.life.mode(), Mode::Closed);
}

#[test]
fn refused() {
    let mut control = Control::new(25_000, 3);
    control.close(0, 0, 0, b"").unwrap();
    assert!(control.close(1, 0, 0, b"").is_err());
}
