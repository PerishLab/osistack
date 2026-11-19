use crate::support::*;
use tls::x509::trust::{Chain, Defect, Roots};
use tls::x509::{Oid, Time};

const EARLY: (&str, &str) = ("260101000000Z", "270101000000Z");
const LATE: (&str, &str) = ("280101000000Z", "300101000000Z");

fn now() -> Time {
    Time {
        year: 2027,
        month: 6,
        day: 15,
        hour: 12,
        minute: 0,
        second: 0,
    }
}

fn root() -> Spec {
    Spec::new("root", "root", 1).ca(None)
}

fn inter() -> Spec {
    Spec::new("inter", "root", 2).ca(None)
}

fn leaf() -> Spec {
    Spec::new("leaf", "inter", 3)
}

fn roots(specs: &[Spec]) -> Roots {
    let mut found = Roots::default();
    for spec in specs {
        found.add(&spec.der()).unwrap();
    }
    found
}

fn link(top: &Spec, pool: &[Spec], held: &Roots) -> Result<Chain, Defect> {
    let certs: Vec<_> = pool.iter().map(|spec| spec.cert()).collect();
    Chain::build(&top.cert(), &certs, held, now())
}

fn names(chain: &Chain) -> Vec<String> {
    let common = Oid::from(&[2, 5, 4, 3]);
    let text = |cert: &tls::x509::Certificate| cert.subject.text(&common).unwrap();
    chain.certs().iter().map(text).collect()
}

fn refused(top: &Spec, pool: &[Spec], held: &Roots) -> Defect {
    link(top, pool, held).unwrap_err()
}

#[test]
fn direct() {
    let held = roots(&[root()]);
    let chain = link(&Spec::new("leaf", "root", 3), &[], &held).unwrap();
    assert_eq!(names(&chain), ["leaf", "root"]);
}

#[test]
fn through() {
    let held = roots(&[root()]);
    let odd = Spec::new("odd", "root", 9).ca(None);
    let far = Spec::new("far", "near", 8).ca(None);
    for pool in [
        vec![inter()],
        vec![odd.clone(), inter(), far.clone()],
        vec![far, inter(), odd],
    ] {
        let chain = link(&leaf(), &pool, &held).unwrap();
        assert_eq!(names(&chain), ["leaf", "inter", "root"]);
    }
    let low = Spec::new("low", "inter", 4).ca(None);
    let top = Spec::new("leaf", "low", 3);
    let chain = link(&top, &[inter(), low], &held).unwrap();
    assert_eq!(names(&chain), ["leaf", "low", "inter", "root"]);
}

#[test]
fn missing() {
    let held = roots(&[root()]);
    assert_eq!(refused(&leaf(), &[], &held), Defect::Unlinked);
    assert_eq!(
        refused(&leaf(), &[inter()], &Roots::default()),
        Defect::Unlinked
    );
    let lost = Spec::new("inter", "nobody", 2).ca(None);
    assert_eq!(refused(&leaf(), &[lost], &held), Defect::Unlinked);
    assert_eq!(refused(&leaf(), &[root()], &held), Defect::Unlinked);
}

#[test]
fn pinned() {
    let held = roots(&[root()]);
    assert_eq!(names(&link(&root(), &[], &held).unwrap()), ["root"]);
    let lone = Spec::new("lone", "lone", 5);
    let held = roots(std::slice::from_ref(&lone));
    assert_eq!(names(&link(&lone, &[], &held).unwrap()), ["lone"]);
    let other = Spec::new("lone", "lone", 6);
    assert_eq!(names(&link(&other, &[], &held).unwrap()), ["lone", "lone"]);
}

#[test]
fn dated() {
    let held = |root: Spec| roots(&[root]);
    let edges = [
        ("270615120000Z", "300101000000Z", true),
        ("260101000000Z", "270615120000Z", true),
        ("270615120001Z", "300101000000Z", false),
        ("260101000000Z", "270615115959Z", false),
    ];
    for (from, until, fine) in edges {
        let want = if fine { None } else { Some(Defect::Dated) };
        let leaf = Spec::new("leaf", "inter", 3).window(from, until);
        let mid = inter().window(from, until);
        let top = root().window(from, until);
        let ok = Spec::new("ok", "ok", 7).ca(None);
        let pool = [inter()];
        let one = failure(&leaf, &pool, &held(root()));
        let two = failure(&Spec::new("leaf", "inter", 3), &[mid], &held(root()));
        let three = failure(&Spec::new("leaf", "inter", 3), &pool, &held(top));
        assert_eq!((one, two, three), (want, want, want), "{from} {until}");
        assert!(link(&ok, &[], &held(ok.clone())).is_ok());
    }
    assert_eq!(
        refused(&leaf().window(EARLY.0, EARLY.1), &[inter()], &held(root())),
        Defect::Dated
    );
    assert_eq!(
        refused(&leaf().window(LATE.0, LATE.1), &[inter()], &held(root())),
        Defect::Dated
    );
}

fn failure(top: &Spec, pool: &[Spec], held: &Roots) -> Option<Defect> {
    link(top, pool, held).err()
}

#[test]
fn authority() {
    let held = roots(&[root()]);
    let bare = Spec::new("inter", "root", 2);
    assert_eq!(refused(&leaf(), &[bare], &held), Defect::Authority);
    let plain = Spec::new("inter", "root", 2).notca();
    assert_eq!(refused(&leaf(), &[plain], &held), Defect::Authority);
    let weak = roots(&[Spec::new("root", "root", 1).notca()]);
    assert_eq!(refused(&leaf(), &[inter()], &weak), Defect::Authority);
    let bare = roots(&[Spec::new("root", "root", 1)]);
    assert!(link(&leaf(), &[inter()], &bare).is_ok());
}

#[test]
fn usage() {
    let held = roots(&[root()]);
    for (byte, fine) in [(0x04, true), (0x84, true), (0x80, false), (0x20, false)] {
        let pool = [inter().usage(byte)];
        assert_eq!(link(&leaf(), &pool, &held).is_ok(), fine, "{byte}");
    }
    for (byte, fine) in [(0x04, true), (0x80, false)] {
        let held = roots(&[root().usage(byte)]);
        assert_eq!(link(&leaf(), &[inter()], &held).is_ok(), fine, "{byte}");
    }
    let held = roots(&[root()]);
    let bad = leaf().usage(0x04);
    assert!(link(&bad, &[inter()], &held).is_ok());
    assert_eq!(
        refused(&leaf(), &[inter().usage(0x80)], &held),
        Defect::Usage
    );
}

#[test]
fn depth() {
    let low = Spec::new("low", "inter", 4).ca(None);
    let top = Spec::new("leaf", "low", 3);
    for (max, fine) in [(0, false), (1, true), (2, true)] {
        let held = roots(&[Spec::new("root", "root", 1).ca(Some(max))]);
        assert_eq!(
            link(&top, &[inter(), low.clone()], &held).is_ok(),
            max >= 2,
            "{max}"
        );
        assert_eq!(link(&leaf(), &[inter()], &held).is_ok(), fine, "{max}");
    }
    let held = roots(&[Spec::new("root", "root", 1).ca(Some(0))]);
    assert!(link(&Spec::new("leaf", "root", 3), &[], &held).is_ok());
    assert_eq!(refused(&leaf(), &[inter()], &held), Defect::Depth);
    let held = roots(&[root()]);
    let tight = Spec::new("inter", "root", 2).ca(Some(0));
    assert!(link(&leaf(), std::slice::from_ref(&tight), &held).is_ok());
    assert_eq!(refused(&top, &[tight, low], &held), Defect::Depth);
}

#[test]
fn turned() {
    let held = |depth| roots(&[Spec::new("B", "B", 1).ca(Some(depth))]);
    let pool = [
        Spec::new("A", "A", 7).ca(None),
        Spec::new("A", "B", 6).ca(None),
    ];
    let top = Spec::new("leaf", "A", 3);
    let chain = link(&top, &pool, &held(1)).unwrap();
    assert_eq!(names(&chain), ["leaf", "A", "A", "B"]);
    assert_eq!(refused(&top, &pool, &held(0)), Defect::Depth);
    let plain = [
        Spec::new("A", "C", 7).ca(None),
        Spec::new("C", "B", 6).ca(None),
    ];
    assert!(link(&top, &plain, &held(2)).is_ok());
    assert_eq!(refused(&top, &plain, &held(1)), Defect::Depth);
}

#[test]
fn purpose() {
    let held = roots(&[root()]);
    for (ids, fine) in [
        (vec![CLIENT], false),
        (vec![SERVER], true),
        (vec![ANY], true),
        (vec![CLIENT, SERVER], true),
    ] {
        let top = leaf().serves(&ids);
        let mid = inter().serves(&ids);
        assert_eq!(link(&top, &[inter()], &held).is_ok(), fine);
        assert_eq!(link(&leaf(), &[mid], &held).is_ok(), fine);
        let held = roots(&[root().serves(&ids)]);
        assert!(link(&leaf(), &[inter()], &held).is_ok());
    }
    assert_eq!(
        refused(&leaf().serves(&[CLIENT]), &[inter()], &held),
        Defect::Purpose
    );
}

#[test]
fn critical() {
    let held = roots(&[root()]);
    let hard = |top: Spec, mid: Spec, base: Spec| link(&top, &[mid], &roots(&[base])).err();
    let flaw = Some(Defect::Critical);
    assert_eq!(hard(leaf().extra(true), inter(), root()), flaw);
    assert_eq!(hard(leaf(), inter().extra(true), root()), flaw);
    assert_eq!(hard(leaf(), inter(), root().extra(true)), flaw);
    assert_eq!(
        hard(
            leaf().extra(false),
            inter().extra(false),
            root().extra(false)
        ),
        None
    );
    assert_eq!(hard(leaf(), inter().urgent(), root().urgent()), None);
    assert!(link(&leaf(), &[inter().urgent()], &held).is_ok());
}

#[test]
fn cycles() {
    let held = roots(&[Spec::new("other", "other", 9).ca(None)]);
    let one = Spec::new("a", "b", 4).ca(None);
    let two = Spec::new("b", "a", 5).ca(None);
    let top = Spec::new("leaf", "a", 3);
    assert_eq!(refused(&top, &[one, two], &held), Defect::Unlinked);
    let lone = Spec::new("s", "s", 6).ca(None);
    assert_eq!(
        refused(&Spec::new("leaf", "s", 3), &[lone], &held),
        Defect::Unlinked
    );
}

#[test]
fn long() {
    let held = roots(&[root()]);
    for (count, fine) in [(1usize, true), (8, true), (9, false), (12, false)] {
        let mut pool = Vec::new();
        for at in 0..count {
            let issuer = if at + 1 == count {
                "root".to_string()
            } else {
                format!("i{}", at + 1)
            };
            pool.push(Spec::new(&format!("i{at}"), &issuer, at as u8 + 10).ca(None));
        }
        let top = Spec::new("leaf", "i0", 3);
        let found = link(&top, &pool, &held);
        assert_eq!(found.is_ok(), fine, "{count}");
        if let Err(defect) = found {
            assert_eq!(defect, Defect::Long);
        }
        if let Ok(chain) = found {
            assert_eq!(chain.certs().len(), count + 2);
        }
    }
}
