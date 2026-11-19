use crate::support::*;
use h2::Misuse;

#[test]
fn exact() {
    let name = "ab";
    let limit = 100;
    let fit = pair(name, &"v".repeat(limit - 32 - name.len()));
    let over = pair(name, &"v".repeat(limit - 32 - name.len() + 1));
    let mut connection = ready(&[(6, limit as u32)]);
    assert_eq!(connection.headers(1, &[over], false), Err(Misuse::Large));
    assert_eq!(connection.encoder().size(), 0);
    assert!(connection.encoder().dynamic().is_empty());
    connection.headers(1, &[fit], false).unwrap();
    assert_eq!(connection.encoder().size(), limit);
}

#[test]
fn summed() {
    let mut connection = ready(&[(6, 100)]);
    let each = |value: usize| [pair("a", &"v".repeat(value)), pair("b", &"v".repeat(17))];
    assert_eq!(connection.headers(1, &each(18), false), Err(Misuse::Large));
    connection.headers(1, &each(17), false).unwrap();
}

#[test]
fn unlimited() {
    let mut connection = ready(&[]);
    let big = pair("x", &"v".repeat(200_000));
    connection.headers(1, &[big], false).unwrap();
}
