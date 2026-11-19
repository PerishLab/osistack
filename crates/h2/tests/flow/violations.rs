use h2::{Code, Fault, Flow, Misuse};

const CONNECTION: Fault = Fault::Connection { code: Code::Flow };

fn stream(id: u32) -> Fault {
    Fault::Stream {
        stream: id,
        code: Code::Flow,
    }
}

fn opened() -> Flow {
    let mut flow = Flow::new();
    flow.open(1);
    flow
}

#[test]
fn code() {
    assert_eq!(Code::Flow.get(), 3);
}

#[test]
fn connection() {
    let mut flow = opened();
    flow.receive(1, 65_535).unwrap();
    assert_eq!(flow.receive(1, 1), Err(CONNECTION));
}

#[test]
fn lone() {
    let mut flow = opened();
    flow.open(3);
    flow.receive(1, 65_535).unwrap();
    flow.grant(0, 65_535).unwrap();
    assert_eq!(flow.receive(1, 1), Err(stream(1)));
    assert_eq!(flow.incoming(1), Some(0));
}

#[test]
fn charged() {
    let mut flow = opened();
    flow.receive(1, 60_000).unwrap();
    flow.grant(0, 10_000).unwrap();
    assert_eq!(flow.receive(1, 6000), Err(stream(1)));
    assert_eq!(flow.incoming(0), Some(75_535 - 60_000 - 6000));
    assert_eq!(flow.incoming(1), Some(5535));
}

#[test]
fn untracked() {
    let mut flow = Flow::new();
    flow.receive(7, 1000).unwrap();
    assert_eq!(flow.incoming(0), Some(64_535));
    assert_eq!(flow.receive(7, 65_000), Err(CONNECTION));
}

#[test]
fn zero() {
    let mut flow = opened();
    assert_eq!(
        flow.credit(0, 0),
        Err(Fault::Connection {
            code: Code::Protocol
        })
    );
    assert_eq!(
        flow.credit(1, 0),
        Err(Fault::Stream {
            stream: 1,
            code: Code::Protocol
        })
    );
    assert_eq!(flow.grant(1, 0), Err(Misuse::Increment));
    assert_eq!(flow.grant(0, 0), Err(Misuse::Increment));
}

#[test]
fn overflow() {
    let mut flow = opened();
    flow.credit(0, 0x7fff_ffff - 65_535).unwrap();
    assert_eq!(flow.outgoing(0), Some(0x7fff_ffff));
    assert_eq!(flow.credit(0, 1), Err(CONNECTION));
    flow.credit(1, 0x7fff_ffff - 65_535).unwrap();
    assert_eq!(flow.credit(1, 1), Err(stream(1)));
    assert_eq!(flow.outgoing(1), Some(0x7fff_ffff));
    assert_eq!(flow.grant(1, 0x7fff_ffff), Err(Misuse::Increment));
    assert_eq!(flow.incoming(1), Some(65_535));
}

#[test]
fn unknown() {
    let mut flow = Flow::new();
    flow.credit(5, 100).unwrap();
    assert_eq!(flow.grant(5, 100), Err(Misuse::Closed));
    assert_eq!(flow.outgoing(5), None);
}

#[test]
fn oversize() {
    let mut flow = opened();
    assert_eq!(flow.local(0x8000_0000), Err(CONNECTION));
    assert_eq!(flow.remote(0x8000_0000), Err(CONNECTION));
    flow.local(0x7fff_ffff).unwrap();
    flow.remote(0x7fff_ffff).unwrap();
    assert_eq!(flow.incoming(1), Some(0x7fff_ffff));
    assert_eq!(flow.outgoing(1), Some(0x7fff_ffff));
}

#[test]
fn rollback() {
    let mut flow = opened();
    flow.open(3);
    flow.credit(3, 1000).unwrap();
    flow.remote(65_535 + 1_000_000).unwrap();
    flow.credit(3, 0x7fff_ffff - 65_535 - 1_000_000 - 1000)
        .unwrap();
    let before = (flow.outgoing(1), flow.outgoing(3));
    assert_eq!(flow.remote(65_535 + 1_000_001), Err(CONNECTION));
    assert_eq!((flow.outgoing(1), flow.outgoing(3)), before);
    flow.open(5);
    assert_eq!(flow.outgoing(5), Some(65_535 + 1_000_000));
}
