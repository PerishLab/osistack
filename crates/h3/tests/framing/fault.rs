use h3::{Code, Fault};

#[test]
fn values() {
    let all = [
        (Code::Clean, 0x100),
        (Code::General, 0x101),
        (Code::Internal, 0x102),
        (Code::Creation, 0x103),
        (Code::Critical, 0x104),
        (Code::Unexpected, 0x105),
        (Code::Frame, 0x106),
        (Code::Load, 0x107),
        (Code::Id, 0x108),
        (Code::Setting, 0x109),
        (Code::Missing, 0x10a),
        (Code::Rejected, 0x10b),
        (Code::Cancelled, 0x10c),
        (Code::Incomplete, 0x10d),
        (Code::Message, 0x10e),
        (Code::Connect, 0x10f),
        (Code::Version, 0x110),
        (Code::Decompress, 0x200),
        (Code::Encode, 0x201),
        (Code::Decode, 0x202),
    ];
    for (code, value) in all {
        assert_eq!(code.get(), value);
        assert_eq!(Code::of(value), Some(code));
    }
    assert_eq!(Code::of(0x111), None);
    assert_eq!(Code::of(0x203), None);
    assert_eq!(Code::of(0), None);
}

#[test]
fn which() {
    let connection = Fault::Connection { code: Code::Id };
    let stream = Fault::Stream {
        code: Code::Message,
    };
    assert_eq!(connection.code(), Code::Id);
    assert_eq!(stream.code(), Code::Message);
}
