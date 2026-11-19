use quic::{Life, Mode, stateless};

fn secret(seed: u8) -> [u8; 16] {
    let mut token = [0u8; 16];
    for (at, byte) in token.iter_mut().enumerate() {
        *byte = seed.wrapping_mul(31).wrapping_add(at as u8 * 7 + 1);
    }
    token
}

fn datagram(size: usize, token: &[u8; 16]) -> Vec<u8> {
    let mut data: Vec<u8> = (0..size).map(|at| (at * 13 + 5) as u8).collect();
    let from = size - 16;
    data[from..].copy_from_slice(token);
    data
}

#[test]
fn tail() {
    let token = secret(1);
    assert!(stateless(&datagram(40, &token), &[token]));
}

#[test]
fn other() {
    assert!(!stateless(&datagram(40, &secret(1)), &[secret(2)]));
}

#[test]
fn bound() {
    let token = secret(3);
    assert!(!stateless(&datagram(16, &token), &[token]));
    assert!(!stateless(&datagram(20, &token), &[token]));
    assert!(stateless(&datagram(21, &token), &[token]));
    assert!(stateless(&datagram(22, &token), &[token]));
    assert!(!stateless(&[], &[token]));
}

#[test]
fn which() {
    let tokens = [secret(1), secret(2), secret(3)];
    for token in &tokens {
        assert!(stateless(&datagram(30, token), &tokens));
    }
    assert!(!stateless(&datagram(30, &secret(4)), &tokens));
}

#[test]
fn empty() {
    assert!(!stateless(&datagram(40, &secret(1)), &[]));
}

#[test]
fn middle() {
    let token = secret(5);
    let mut data = datagram(40, &secret(6));
    data[4..20].copy_from_slice(&token);
    assert!(!stateless(&data, &[token]));
    data[..16].copy_from_slice(&token);
    assert!(!stateless(&data, &[token]));
}

#[test]
fn shift() {
    let token = secret(7);
    let mut data = datagram(40, &token);
    data.push(0);
    assert!(!stateless(&data, &[token]));
    let mut data = datagram(41, &token);
    data.remove(0);
    assert!(stateless(&data, &[token]));
    data.truncate(39);
    assert!(!stateless(&data, &[token]));
}

#[test]
fn flip() {
    let token = secret(8);
    for byte in 0..16 {
        for bit in 0..8 {
            let mut data = datagram(30, &token);
            data[14 + byte] ^= 1 << bit;
            assert!(!stateless(&data, &[token]), "byte {byte} bit {bit}");
        }
    }
}

#[test]
fn head() {
    let token = secret(9);
    let mut data = datagram(60, &token);
    for byte in &mut data[..44] {
        *byte = !*byte;
    }
    assert!(stateless(&data, &[token]));
}

#[test]
fn many() {
    let tokens: Vec<[u8; 16]> = (10..18).map(secret).collect();
    assert!(stateless(&datagram(25, &tokens[7]), &tokens));
    assert!(stateless(&datagram(25, &tokens[0]), &tokens));
    assert!(!stateless(&datagram(25, &secret(30)), &tokens));
    let twice = [tokens[2], tokens[2]];
    assert!(stateless(&datagram(25, &tokens[2]), &twice));
}

#[test]
fn drained() {
    let token = secret(11);
    let mut life = Life::default();
    if stateless(&datagram(40, &token), &[token]) {
        life.reset(100, 1_000);
    }
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.deadline(), Some(3_100));
}

#[test]
fn resetting() {
    let mut life = Life::default();
    life.reset(100, 1_000);
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.deadline(), Some(3_100));
    let mut life = Life::default();
    life.close(
        100,
        1_000,
        quic::Frame::Application {
            code: 1,
            reason: Vec::new(),
        },
    )
    .unwrap();
    life.reset(2_000, 5_000);
    assert_eq!(life.mode(), Mode::Draining);
    assert_eq!(life.deadline(), Some(3_100));
}
