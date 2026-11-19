use crate::support::*;
use quic::{Direction, Param, Params, Side};

#[test]
fn identifiers() {
    same(
        "00 08 8394c8f03e515708",
        &[Param::Original(hex("8394c8f03e515708"))],
    );
    same("00 00", &[Param::Original(vec![])]);
    same("0f 04 01020304", &[Param::Source(vec![1, 2, 3, 4])]);
    same("10 00", &[Param::Retry(vec![])]);
    let twenty = "ab".repeat(20);
    same(&format!("10 14 {twenty}"), &[Param::Retry(hex(&twenty))]);
    same(&format!("0f 14 {twenty}"), &[Param::Source(hex(&twenty))]);
    same(&format!("00 14 {twenty}"), &[Param::Original(hex(&twenty))]);
}

#[test]
fn numbers() {
    same("01 04 80007530", &[Param::Idle(30000)]);
    same("01 01 1e", &[Param::Idle(30)]);
    same("03 02 44b0", &[Param::Payload(1200)]);
    same("04 01 00", &[Param::Data(0)]);
    same("0a 01 14", &[Param::Exponent(20)]);
    same("0a 01 03", &[Param::Exponent(3)]);
    same("0b 02 7fff", &[Param::Delay(16383)]);
    same("0e 01 02", &[Param::Limit(2)]);
    same("0e 01 08", &[Param::Limit(8)]);
}

#[test]
fn windows() {
    same("05 02 4400", &[Param::Window(Side::Local, 1024)]);
    same("06 01 10", &[Param::Window(Side::Remote, 16)]);
    same("07 04 8000ffff", &[Param::Window(Side::Uni, 65535)]);
}

#[test]
fn streams() {
    same("08 01 10", &[Param::Streams(Direction::Bidi, 16)]);
    same("09 01 10", &[Param::Streams(Direction::Uni, 16)]);
    let limit = 1 << 60;
    same(
        "08 08 d000000000000000",
        &[Param::Streams(Direction::Bidi, limit)],
    );
    same(
        "09 08 d000000000000000",
        &[Param::Streams(Direction::Uni, limit)],
    );
}

#[test]
fn flags() {
    same("0c 00", &[Param::Migration]);
    same(
        &format!("02 10 {TOKEN}"),
        &[Param::Reset(hex(TOKEN).try_into().unwrap())],
    );
}

#[test]
fn addresses() {
    for size in [1usize, 4, 20] {
        let cid = vec![0xaa; size];
        let length = 4 + 2 + 16 + 2 + 1 + size + 16;
        let text = format!(
            "0d {length:02x} 7f000001 1f90 {} 1f91 {size:02x} {} {TOKEN}",
            "00".repeat(15) + "01",
            "aa".repeat(size)
        );
        same(&text, &[Param::Address(address(&cid))]);
    }
}

#[test]
fn unknown() {
    same("1b 02 aabb", &[Param::Other(27, vec![0xaa, 0xbb])]);
    same("11 00", &[Param::Other(0x11, vec![])]);
    same("4078 03 010203", &[Param::Other(120, vec![1, 2, 3])]);
    let big = 31 * (1u64 << 20) + 27;
    let text = format!("{:08x} 01 ff", 0x8000_0000 | big);
    same(&text, &[Param::Other(big, vec![0xff])]);
}

#[test]
fn order() {
    same("04 01 05 01 01 06", &[Param::Data(5), Param::Idle(6)]);
    same("01 01 06 04 01 05", &[Param::Idle(6), Param::Data(5)]);
    same(
        "1b 00 0c 00 01 01 01",
        &[Param::Other(27, vec![]), Param::Migration, Param::Idle(1)],
    );
}

#[test]
fn nothing() {
    assert_eq!(Params::parse(&[]).unwrap().list, vec![]);
    assert_eq!(Params::default().write().unwrap(), Vec::<u8>::new());
}

#[test]
fn padded() {
    let found = Params::parse(&hex("01 04 80000001")).unwrap();
    assert_eq!(found.list, vec![Param::Idle(1)]);
    assert_eq!(found.write().unwrap(), hex("01 01 01"));
    let wide = Params::parse(&hex("04 08 c000000000000005")).unwrap();
    assert_eq!(wide.list, vec![Param::Data(5)]);
    assert_eq!(wide.write().unwrap(), hex("04 01 05"));
    let two = Params::parse(&hex("05 02 4005")).unwrap();
    assert_eq!(two.write().unwrap(), hex("05 01 05"));
}
