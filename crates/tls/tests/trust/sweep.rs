use crate::support::{Dice, build, dns, name, pem};
use tls::x509::Name;
use tls::x509::trust::Roots;

fn notes(dice: &mut Dice) -> String {
    let mut out = String::new();
    for _ in 0..dice.below(3) {
        out.push_str(&format!("note {} about roots\n", dice.below(1000)));
    }
    out
}

#[test]
fn bundle() {
    for seed in 1..=64u64 {
        let mut dice = Dice::new(seed);
        let count = 1 + dice.below(6);
        let eol = ["\n", "\r\n", "\r"][dice.below(3)];
        let width = 1 + dice.below(100);
        let mut text = notes(&mut dice);
        let mut ders = Vec::new();
        for at in 0..count {
            let subject = format!("cert{seed}-{at}");
            let der = build(&name(&subject), "root", Some(&[dns("x.example")]), at as u8);
            text.push_str(&pem("CERTIFICATE", &der, width, eol));
            text.push_str(&notes(&mut dice));
            if dice.below(3) == 0 {
                text.push_str(&pem("PRIVATE KEY", &dice.bytes(40), width, eol));
            }
            ders.push((subject, der));
        }
        let roots = Roots::pem(&text).unwrap();
        assert_eq!(roots.count(), count, "seed {seed}");
        for (subject, der) in &ders {
            assert!(roots.contains(der), "seed {seed}");
            let issuer = Name::parse(&name(subject)).unwrap();
            assert_eq!(roots.anchors(&issuer).len(), 1, "seed {seed}");
        }
    }
}
