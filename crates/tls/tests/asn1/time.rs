use crate::support::when;
use tls::x509::{Flaw, Time};

const UTC: u8 = 0x17;
const GENERAL: u8 = 0x18;

fn utc(text: &str) -> Result<Time, Flaw> {
    Time::parse(UTC, text.as_bytes())
}

fn general(text: &str) -> Result<Time, Flaw> {
    Time::parse(GENERAL, text.as_bytes())
}

#[test]
fn formats() {
    assert_eq!(utc("260102030405Z"), Ok(when((2026, 1, 2), (3, 4, 5))));
    assert_eq!(
        general("20260102030405Z"),
        Ok(when((2026, 1, 2), (3, 4, 5)))
    );
    assert_eq!(
        general("19991231235959Z"),
        Ok(when((1999, 12, 31), (23, 59, 59)))
    );
    assert_eq!(
        general("99991231235959Z"),
        Ok(when((9999, 12, 31), (23, 59, 59)))
    );
}

#[test]
fn pivot() {
    assert_eq!(utc("500101000000Z"), Ok(when((1950, 1, 1), (0, 0, 0))));
    assert_eq!(utc("491231235959Z"), Ok(when((2049, 12, 31), (23, 59, 59))));
    assert_eq!(utc("990101000000Z"), Ok(when((1999, 1, 1), (0, 0, 0))));
    assert_eq!(utc("000101000000Z"), Ok(when((2000, 1, 1), (0, 0, 0))));
}

#[test]
fn leaps() {
    assert!(utc("000229000000Z").is_ok());
    assert!(utc("240229235959Z").is_ok());
    assert!(general("20000229000000Z").is_ok());
    assert!(general("20240229000000Z").is_ok());
    assert_eq!(utc("000230000000Z"), Err(Flaw::Time));
    assert_eq!(utc("230229000000Z"), Err(Flaw::Time));
    assert_eq!(general("19000229000000Z"), Err(Flaw::Time));
    assert_eq!(general("21000229000000Z"), Err(Flaw::Time));
    assert_eq!(general("18000229000000Z"), Err(Flaw::Time));
    assert_eq!(general("22000229000000Z"), Err(Flaw::Time));
    assert_eq!(general("20000230000000Z"), Err(Flaw::Time));
    assert_eq!(general("20230229000000Z"), Err(Flaw::Time));
}

#[test]
fn months() {
    assert_eq!(utc("260001000000Z"), Err(Flaw::Time));
    assert_eq!(utc("261301000000Z"), Err(Flaw::Time));
    assert!(utc("261201000000Z").is_ok());
    assert!(utc("260101000000Z").is_ok());
    assert_eq!(utc("260100000000Z"), Err(Flaw::Time));
    assert_eq!(utc("260132000000Z"), Err(Flaw::Time));
    assert!(utc("260131000000Z").is_ok());
    for month in ["04", "06", "09", "11"] {
        assert!(utc(&format!("26{month}30000000Z")).is_ok());
        assert_eq!(utc(&format!("26{month}31000000Z")), Err(Flaw::Time));
    }
    assert!(utc("260228000000Z").is_ok());
    assert_eq!(utc("260229000000Z"), Err(Flaw::Time));
}

#[test]
fn clocks() {
    assert!(utc("260101235959Z").is_ok());
    assert_eq!(utc("260101240000Z"), Err(Flaw::Time));
    assert_eq!(utc("260101236000Z"), Err(Flaw::Time));
    assert_eq!(utc("260101000060Z"), Err(Flaw::Time));
    assert_eq!(utc("260101009999Z"), Err(Flaw::Time));
    assert!(utc("260101005960Z").is_err());
    assert!(utc("260101005959Z").is_ok());
}

#[test]
fn shapes() {
    assert_eq!(utc("260102030405"), Err(Flaw::Time));
    assert_eq!(utc("260102030405z"), Err(Flaw::Time));
    assert_eq!(utc("2601020304Z"), Err(Flaw::Time));
    assert_eq!(utc("260102030405+0800"), Err(Flaw::Time));
    assert_eq!(utc("260102030405-0800"), Err(Flaw::Time));
    assert_eq!(utc("260102030405.5Z"), Err(Flaw::Time));
    assert_eq!(utc("2601020304050Z"), Err(Flaw::Time));
    assert_eq!(utc(""), Err(Flaw::Time));
    assert_eq!(general("20260102030405"), Err(Flaw::Time));
    assert_eq!(general("20260102030405.5Z"), Err(Flaw::Time));
    assert_eq!(general("260102030405Z"), Err(Flaw::Time));
    assert_eq!(general("202601020304Z"), Err(Flaw::Time));
    assert_eq!(utc("20260102030405Z"), Err(Flaw::Time));
}

#[test]
fn digits() {
    assert_eq!(utc("26010a030405Z"), Err(Flaw::Time));
    assert_eq!(utc("+60102030405Z"), Err(Flaw::Time));
    assert_eq!(utc("2601 2030405Z"), Err(Flaw::Time));
    assert_eq!(general("2026-102030405Z"), Err(Flaw::Time));
    assert_eq!(general("a0260102030405Z"), Err(Flaw::Time));
}

#[test]
fn tags() {
    assert_eq!(Time::parse(0x0c, b"260102030405Z"), Err(Flaw::Tag));
    assert_eq!(Time::parse(0x13, b"260102030405Z"), Err(Flaw::Tag));
    assert_eq!(Time::parse(0x16, b"260102030405Z"), Err(Flaw::Tag));
}

#[test]
fn seconds() {
    assert_eq!(when((1970, 1, 1), (0, 0, 0)).unix(), 0);
    assert_eq!(when((1969, 12, 31), (23, 59, 59)).unix(), -1);
    assert_eq!(when((1970, 3, 1), (0, 0, 0)).unix(), 5_097_600);
    assert_eq!(when((1999, 12, 31), (23, 59, 59)).unix(), 946_684_799);
    assert_eq!(when((2000, 2, 29), (0, 0, 0)).unix(), 951_782_400);
    assert_eq!(when((2000, 3, 1), (0, 0, 0)).unix(), 951_868_800);
    assert_eq!(when((2024, 2, 29), (23, 59, 59)).unix(), 1_709_251_199);
    assert_eq!(when((2026, 1, 2), (3, 4, 5)).unix(), 1_767_323_045);
    assert_eq!(when((2038, 1, 19), (3, 14, 8)).unix(), 2_147_483_648);
    assert_eq!(when((2100, 3, 1), (0, 0, 0)).unix(), 4_107_542_400);
    assert_eq!(when((1900, 1, 1), (0, 0, 0)).unix(), -2_208_988_800);
    assert_eq!(when((1, 1, 1), (0, 0, 0)).unix(), -62_135_596_800);
    assert_eq!(when((0, 1, 1), (0, 0, 0)).unix(), -62_167_219_200);
    assert_eq!(when((0, 3, 1), (0, 0, 0)).unix(), -62_162_035_200);
    assert_eq!(when((9999, 12, 31), (23, 59, 59)).unix(), 253_402_300_799);
}

#[test]
fn parsed() {
    assert_eq!(utc("260102030405Z").unwrap().unix(), 1_767_323_045);
    assert_eq!(general("20000301000000Z").unwrap().unix(), 951_868_800);
    assert_eq!(utc("700101000000Z").unwrap().unix(), 0);
}

#[test]
fn order() {
    let base = when((2026, 6, 15), (12, 30, 30));
    assert!(base < when((2027, 1, 1), (0, 0, 0)));
    assert!(base < when((2026, 7, 1), (0, 0, 0)));
    assert!(base < when((2026, 6, 16), (0, 0, 0)));
    assert!(base < when((2026, 6, 15), (13, 0, 0)));
    assert!(base < when((2026, 6, 15), (12, 31, 0)));
    assert!(base < when((2026, 6, 15), (12, 30, 31)));
    assert!(base > when((2025, 12, 31), (23, 59, 59)));
    assert_eq!(base, when((2026, 6, 15), (12, 30, 30)));
}
