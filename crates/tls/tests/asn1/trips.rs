use crate::support::tlv;
use tls::x509::{Der, Flaw};

struct Source(u64);

impl Source {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % bound
    }

    fn bytes(&mut self, longest: usize) -> Vec<u8> {
        let length = self.next(longest + 1);
        (0..length).map(|_| self.next(256) as u8).collect()
    }

    fn tag(&mut self) -> u8 {
        let tags = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x16, 0x30, 0x31];
        tags[self.next(tags.len())]
    }
}

fn read(wire: &[u8]) -> Result<(u8, Vec<u8>), Flaw> {
    let mut der = Der::new(wire);
    let (tag, body) = der.read()?;
    der.finish()?;
    Ok((tag, body.to_vec()))
}

#[test]
fn prefixes() {
    let mut source = Source(19);
    let mut refused = 0;
    for _ in 0..300 {
        let tag = source.tag();
        let body = source.bytes(200);
        let wire = tlv(tag, &body);
        assert_eq!(read(&wire), Ok((tag, body)));
        for cut in 0..wire.len() {
            if read(&wire[..cut]).is_err() {
                refused += 1;
            }
        }
    }
    assert!(refused > 0);
}

#[test]
fn hostile() {
    let mut source = Source(29);
    for _ in 0..300 {
        let wire = tlv(source.tag(), &source.bytes(80));
        let mut damaged = wire.clone();
        let at = source.next(damaged.len());
        damaged[at] = source.next(256) as u8;
        let _ = read(&damaged);
    }
}
