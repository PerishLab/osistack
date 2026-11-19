use crate::support::{Dice, alt, keep, offer, one, origin, parse};
use h3::{Directive, Origin};

#[test]
fn rfc() {
    assert_eq!(
        one("h2=\":8000\""),
        alt("h2", "www.example.com", 8000, 86400)
    );
    assert_eq!(
        one("h2=\"new.example.org:80\""),
        alt("h2", "new.example.org", 80, 86400)
    );
    assert_eq!(
        offer("h2=\"alt.example.com:8000\", h2=\":443\""),
        vec![
            alt("h2", "alt.example.com", 8000, 86400),
            alt("h2", "www.example.com", 443, 86400)
        ]
    );
    assert_eq!(
        one("h2=\":443\"; ma=3600"),
        alt("h2", "www.example.com", 443, 3600)
    );
    assert_eq!(
        one("h2=\":443\"; ma=2592000; persist=1"),
        keep(alt("h2", "www.example.com", 443, 2_592_000))
    );
    assert_eq!(parse("clear"), Ok(Directive::Clear));
}

#[test]
fn blanks() {
    let text = " \th3=\":443\"  ;\t ma=60 ;persist=1 ,\th3=\":444\"\t";
    assert_eq!(
        offer(text),
        vec![
            keep(alt("h3", "www.example.com", 443, 60)),
            alt("h3", "www.example.com", 444, 86400)
        ]
    );
}

#[test]
fn commas() {
    assert_eq!(offer(",, h3=\":443\" ,, ,").len(), 1);
    assert_eq!(offer("h3=\":443\",h3=\":444\"").len(), 2);
    assert_eq!(offer(",h3=\":1\",,h3=\":2\",").len(), 2);
}

#[test]
fn inside() {
    let found = offer("h3=\":443\"; x=\"a,b\", h3=\":444\"");
    assert_eq!(found.len(), 2);
    assert_eq!(found[1].port, 444);
    let found = offer("h3=\":443\"; x=\"a\\\",b\", h3=\":444\"");
    assert_eq!(found.len(), 2);
    assert_eq!(found[1].port, 444);
    assert_eq!(parse("h3=\"a,b:443\""), Err(h3::Defect::Host));
}

#[test]
fn quoted() {
    assert_eq!(one("h3=\"\\w\\w\\w.example:443\"").host, "www.example");
    assert_eq!(one("h3=\":4\\43\"").port, 443);
    assert_eq!(one("h3=\":443\"; x=\"\\\"\"").port, 443);
    assert_eq!(one("h3=\":443\"; x=\"a\\\\\"; ma=7").age, 7);
    assert_eq!(parse("h3=\":443\"; x=\"\\\""), Err(h3::Defect::Syntax));
    assert_eq!(parse("h3=\":443\"; x=\"a\\"), Err(h3::Defect::Syntax));
}

#[test]
fn order() {
    let found = offer("h3=\":443\", h3-29=\":443\", h2=\"alt.example:8443\"");
    let names: Vec<&[u8]> = found.iter().map(|each| each.protocol.as_slice()).collect();
    assert_eq!(names, [&b"h3"[..], &b"h3-29"[..], &b"h2"[..]]);
    assert_eq!(found[2].host, "alt.example");
    assert_eq!(found[2].port, 8443);
}

#[test]
fn home() {
    assert_eq!(Origin::new("Example.COM", 8443).host, "example.com");
    let home = Origin::new("WWW.Example.COM", 443);
    let found = Directive::parse("h3=\":9443\"", &home).unwrap();
    assert_eq!(
        found,
        Directive::Offer(vec![alt("h3", "www.example.com", 9443, 86400)])
    );
    let found = Directive::parse("h3=\":9443\"", &origin()).unwrap();
    assert_eq!(
        found,
        Directive::Offer(vec![alt("h3", "www.example.com", 9443, 86400)])
    );
    let other = Origin::new("other.example", 1);
    let found = Directive::parse("h3=\":9443\"", &other).unwrap();
    assert_eq!(
        found,
        Directive::Offer(vec![alt("h3", "other.example", 9443, 86400)])
    );
}

#[test]
fn fields() {
    for seed in 1..=64u64 {
        let mut dice = Dice::new(seed);
        let home = origin();
        for round in 0..20 {
            let made = dice.build(&home, 3_000_000_000);
            let found = parse(&made.text);
            assert_eq!(
                found,
                Ok(Directive::Offer(made.alts)),
                "seed {seed} round {round}: {:?}",
                made.text
            );
        }
    }
}
