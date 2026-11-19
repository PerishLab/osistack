use h2::{Codec, Flow, Frame, INITIAL, Misuse};

fn opened(streams: &[u32]) -> Flow {
    let mut flow = Flow::new();
    for stream in streams {
        flow.open(*stream);
    }
    flow
}

#[test]
fn initial() {
    let flow = opened(&[1]);
    assert_eq!(INITIAL, 65_535);
    assert_eq!(flow.outgoing(0), Some(65_535));
    assert_eq!(flow.incoming(0), Some(65_535));
    assert_eq!(flow.outgoing(1), Some(65_535));
    assert_eq!(flow.incoming(1), Some(65_535));
    assert_eq!(flow.outgoing(3), None);
    assert_eq!(flow.room(1), 65_535);
    assert_eq!(flow.room(3), 0);
}

#[test]
fn sending() {
    let mut flow = opened(&[1, 3]);
    flow.send(1, 1000).unwrap();
    assert_eq!(flow.outgoing(0), Some(64_535));
    assert_eq!(flow.outgoing(1), Some(64_535));
    assert_eq!(flow.outgoing(3), Some(65_535));
    assert_eq!(flow.room(3), 64_535);
    flow.send(3, 0).unwrap();
    assert_eq!(flow.outgoing(0), Some(64_535));
}

#[test]
fn receiving() {
    let mut flow = opened(&[1, 3]);
    flow.receive(3, 500).unwrap();
    assert_eq!(flow.incoming(0), Some(65_035));
    assert_eq!(flow.incoming(3), Some(65_035));
    assert_eq!(flow.incoming(1), Some(65_535));
}

#[test]
fn smaller() {
    let mut flow = opened(&[1, 3]);
    flow.send(1, 65_000).unwrap();
    assert_eq!(flow.room(3), 535);
    assert_eq!(flow.send(3, 536), Err(Misuse::Window));
    flow.send(3, 535).unwrap();
    assert_eq!(flow.room(1), 0);
    assert_eq!(flow.room(3), 0);
}

#[test]
fn exhausted() {
    let mut flow = opened(&[1]);
    flow.send(1, 65_535).unwrap();
    assert_eq!(flow.send(1, 1), Err(Misuse::Window));
    flow.send(1, 0).unwrap();
    assert_eq!(flow.outgoing(1), Some(0));
}

#[test]
fn credited() {
    let mut flow = opened(&[1]);
    flow.send(1, 65_535).unwrap();
    flow.credit(1, 100).unwrap();
    assert_eq!(flow.room(1), 0);
    flow.credit(0, 70).unwrap();
    assert_eq!(flow.room(1), 70);
    assert_eq!(flow.outgoing(0), Some(70));
    assert_eq!(flow.outgoing(1), Some(100));
}

#[test]
fn granted() {
    let mut flow = opened(&[1]);
    flow.receive(1, 65_535).unwrap();
    flow.grant(1, 65_535).unwrap();
    flow.grant(0, 65_535).unwrap();
    assert_eq!(flow.incoming(1), Some(65_535));
    assert_eq!(flow.incoming(0), Some(65_535));
    flow.receive(1, 65_535).unwrap();
}

#[test]
fn wire() {
    let codec = Codec::default();
    let bytes = [0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0x10, 0];
    let (frame, used) = codec.decode(&bytes).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    let Frame::Window { stream, increment } = frame else {
        panic!("not a window update");
    };
    let mut flow = opened(&[1]);
    flow.send(1, 65_535).unwrap();
    flow.credit(stream, increment).unwrap();
    assert_eq!(flow.outgoing(1), Some(4096));
    let data = [0, 0, 3, 0, 0, 0, 0, 0, 1, b'a', b'b', b'c'];
    let (frame, _) = codec.decode(&data).unwrap().unwrap();
    assert_eq!(Flow::cost(&frame), Some(3));
}

#[test]
fn padding() {
    let padded = Frame::Data {
        stream: 1,
        fin: false,
        pad: Some(9),
        data: vec![0; 5],
    };
    assert_eq!(Flow::cost(&padded), Some(15));
    let bare = Frame::Data {
        stream: 1,
        fin: false,
        pad: Some(0),
        data: Vec::new(),
    };
    assert_eq!(Flow::cost(&bare), Some(1));
    let other = Frame::Reset { stream: 1, code: 0 };
    assert_eq!(Flow::cost(&other), None);
}

#[test]
fn closing() {
    let mut flow = opened(&[1]);
    flow.close(1);
    assert_eq!(flow.outgoing(1), None);
    assert_eq!(flow.send(1, 1), Err(Misuse::Closed));
    assert_eq!(flow.send(0, 1), Err(Misuse::Zero));
    flow.open(1);
    flow.send(1, 10).unwrap();
    flow.open(1);
    assert_eq!(flow.outgoing(1), Some(65_525));
}

#[test]
fn changing() {
    let mut flow = opened(&[1]);
    flow.send(1, 60_000).unwrap();
    flow.remote(10_000).unwrap();
    assert_eq!(flow.outgoing(1), Some(-50_000));
    assert_eq!(flow.outgoing(0), Some(5535));
    assert_eq!(flow.room(1), 0);
    flow.send(1, 0).unwrap();
    assert_eq!(flow.send(1, 1), Err(Misuse::Window));
    flow.credit(1, 50_001).unwrap();
    assert_eq!(flow.outgoing(1), Some(1));
    flow.open(3);
    assert_eq!(flow.outgoing(3), Some(10_000));
    assert_eq!(flow.room(3), 5535);
}

#[test]
fn ours() {
    let mut flow = opened(&[1]);
    flow.receive(1, 1000).unwrap();
    flow.local(100_000).unwrap();
    assert_eq!(flow.incoming(1), Some(99_000));
    assert_eq!(flow.incoming(0), Some(64_535));
    flow.open(3);
    assert_eq!(flow.incoming(3), Some(100_000));
    flow.local(0).unwrap();
    assert_eq!(flow.incoming(3), Some(0));
    assert_eq!(flow.incoming(1), Some(-1000));
}
