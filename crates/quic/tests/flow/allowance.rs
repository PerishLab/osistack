use crate::support::*;
use quic::{Allowance, Fault};

fn open(limit: u64) -> Allowance {
    Allowance::new(limit, Fault::Flow)
}

#[test]
fn exact() {
    let mut allowance = open(100);
    assert_eq!(allowance.accept(100), Ok(100));
    assert_eq!(allowance.accept(101), Err(Fault::Flow));
    assert_eq!(allowance.highest(), 100);
    assert_eq!(allowance.limit(), 100);
}

#[test]
fn refused() {
    let mut allowance = open(100);
    assert_eq!(allowance.accept(50), Ok(50));
    assert_eq!(allowance.accept(101), Err(Fault::Flow));
    assert_eq!(allowance.accept(u64::MAX), Err(Fault::Flow));
    assert_eq!(allowance.highest(), 50);
    assert_eq!(allowance.accept(100), Ok(50));
}

#[test]
fn fault() {
    let mut allowance = Allowance::new(4, Fault::Limit);
    assert_eq!(allowance.accept(5), Err(Fault::Limit));
    assert_eq!(allowance.accept(4), Ok(4));
}

#[test]
fn fresh() {
    let mut allowance = open(1000);
    let ends = [30, 10, 30, 50, 40, 50, 51];
    let found: Vec<u64> = ends
        .iter()
        .map(|end| allowance.accept(*end).unwrap())
        .collect();
    assert_eq!(found, vec![30, 0, 0, 20, 0, 0, 1]);
    assert_eq!(allowance.highest(), 51);
    assert_eq!(allowance.accept(0), Ok(0));
}

#[test]
fn charged() {
    let mut allowance = open(100);
    assert_eq!(allowance.charge(10), Ok(10));
    assert_eq!(allowance.charge(5), Ok(5));
    assert_eq!(allowance.charge(0), Ok(0));
    assert_eq!(allowance.highest(), 15);
    assert_eq!(allowance.charge(86), Err(Fault::Flow));
    assert_eq!(allowance.highest(), 15);
    assert_eq!(allowance.charge(85), Ok(85));
    assert_eq!(allowance.charge(u64::MAX), Err(Fault::Flow));
}

#[test]
fn consumed() {
    let mut allowance = open(100);
    allowance.accept(10).unwrap();
    allowance.consume(4);
    assert_eq!(allowance.consumed(), 4);
    allowance.consume(100);
    assert_eq!(allowance.consumed(), 10);
    allowance.consume(u64::MAX);
    assert_eq!(allowance.consumed(), 10);
}

#[test]
fn granting() {
    let mut allowance = open(100);
    allowance.accept(100).unwrap();
    allowance.consume(49);
    assert_eq!(allowance.grant(), None);
    allowance.consume(1);
    assert_eq!(allowance.grant(), Some(150));
    assert_eq!(allowance.limit(), 150);
    assert_eq!(allowance.grant(), None);
    allowance.accept(150).unwrap();
    allowance.consume(49);
    assert_eq!(allowance.grant(), None);
    allowance.consume(1);
    assert_eq!(allowance.grant(), Some(200));
    assert_eq!(allowance.grant(), None);
}

#[test]
fn windows() {
    let mut zero = open(0);
    assert_eq!(zero.accept(0), Ok(0));
    assert_eq!(zero.grant(), None);
    assert_eq!(zero.accept(1), Err(Fault::Flow));
    let mut odd = open(5);
    odd.accept(5).unwrap();
    odd.consume(1);
    assert_eq!(odd.grant(), None);
    odd.consume(1);
    assert_eq!(odd.grant(), Some(7));
    let mut one = open(1);
    assert_eq!(one.grant(), None);
    one.accept(1).unwrap();
    assert_eq!(one.grant(), None);
    one.consume(1);
    assert_eq!(one.grant(), Some(2));
}

fn churn(dice: &mut Dice, allowance: &mut Allowance) {
    match dice.below(3) {
        0 => {
            let _ = allowance.accept(dice.below(400));
        }
        1 => allowance.consume(dice.below(20)),
        _ => {
            let _ = allowance.grant();
        }
    }
}

#[test]
fn grown() {
    for seed in 1..=40 {
        let mut dice = Dice::new(seed);
        let mut allowance = open(dice.within(1, 64));
        let mut before = allowance.limit();
        for _ in 0..200 {
            churn(&mut dice, &mut allowance);
            assert!(allowance.limit() >= before);
            assert!(allowance.highest() <= allowance.limit());
            assert!(allowance.consumed() <= allowance.highest());
            before = allowance.limit();
        }
    }
}
