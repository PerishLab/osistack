use crate::support::*;
use quic::Reno;

fn recovered() -> Reno {
    let mut reno = Reno::new(1200, 25_000);
    reno.lost(500, &[packet(0, 100)], &measured());
    reno
}

fn ack(reno: &mut Reno, count: u64, time: u64) -> Vec<u64> {
    let mut seen = Vec::new();
    for number in 0..count {
        reno.acked(&[packet(number, time)]);
        seen.push(reno.window());
    }
    seen
}

#[test]
fn boundary() {
    let mut reno = recovered();
    reno.acked(&[packet(1, 501)]);
    assert_eq!(reno.window(), 6_000);
}

#[test]
fn linear() {
    let mut reno = recovered();
    assert_eq!(ack(&mut reno, 5, 501), [6_000, 6_000, 6_000, 6_000, 7_200]);
    assert_eq!(
        ack(&mut reno, 6, 501),
        [7_200, 7_200, 7_200, 7_200, 7_200, 8_400]
    );
}

#[test]
fn large() {
    let mut reno = recovered();
    let big = quic::Sent {
        size: 15_000,
        ..packet(1, 501)
    };
    reno.acked(&[big]);
    assert_eq!(reno.window(), 8_400);
    reno.acked(&[packet(2, 501), packet(3, 501)]);
    assert_eq!(reno.window(), 8_400);
    reno.acked(&[
        packet(4, 501),
        packet(5, 501),
        packet(6, 501),
        packet(7, 501),
    ]);
    assert_eq!(reno.window(), 9_600);
}

#[test]
fn started() {
    let mut reno = recovered();
    assert_eq!(ack(&mut reno, 4, 501), [6_000, 6_000, 6_000, 6_000]);
    reno.lost(700, &[packet(9, 600)], &measured());
    assert_eq!(reno.window(), 3_000);
    assert_eq!(ack(&mut reno, 3, 701), [3_000, 3_000, 4_200]);
}

#[test]
fn counted() {
    let mut reno = recovered();
    let batch = [
        packet(1, 500),
        packet(2, 501),
        packet(3, 501),
        packet(4, 501),
        packet(5, 501),
    ];
    reno.acked(&batch);
    assert_eq!(reno.window(), 6_000);
    reno.acked(&[packet(6, 501)]);
    assert_eq!(reno.window(), 7_200);
}
