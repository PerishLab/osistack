use quic::Fault;

#[test]
fn codes() {
    assert_eq!(Fault::Flow.code(), 0x3);
    assert_eq!(Fault::Limit.code(), 0x4);
    assert_eq!(Fault::State.code(), 0x5);
    assert_eq!(Fault::Final.code(), 0x6);
}
